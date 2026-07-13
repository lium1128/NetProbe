"""插件基类 — 所有检测插件的抽象接口。

每个插件声明自己的元信息（名称/描述/分类/阶段），
实现 run(hosts, options) 方法执行检测。

约定:
  - run() 就地修改 hosts 列表中的每个 host dict
  - 漏洞追加到 host['vulnerabilities']，探测写入 host['_xxx_findings']
  - 返回发现数（int），0 表示无发现
  - run() 内部自行 try/except，异常不应抛出到调用方
"""
from abc import ABC, abstractmethod
from typing import Callable


class Plugin(ABC):
    """检测插件基类。"""

    # ── 元信息（子类必须覆盖）──
    name: str = ''           # 唯一标识（英文，如 'ssl_check'）
    display_name: str = ''   # 显示名（中文，如 'SSL/TLS 深度检测'）
    description: str = ''    # 一句话描述
    category: str = 'vuln'   # vuln / recon / info
    stage: str = 'vuln'      # 关联的阶段开关（vuln / web / sensitive / port 等）
    icon: str = '🔌'         # 前端展示图标（emoji）
    is_builtin: bool = True  # 内置插件标记（外部插件为 False）

    @abstractmethod
    def run(self, hosts: list[dict], options: dict, emit: Callable | None = None) -> int:
        """执行检测。

        参数:
            hosts: 主机列表（就地修改）
            options: 扫描配置（含 stages / timeout / nuclei_severity 等）
            emit: 进度回调 emit(event, **data)，可选

        返回: 发现数（int），0 表示无发现。
        """
        ...

    def is_available(self) -> bool:
        """检查依赖是否满足（如外部命令/库是否安装）。

        返回 False 时插件在前端显示为「未就绪」，不可启用。
        默认 True。
        """
        return True

    def to_dict(self) -> dict:
        """序列化为前端展示用的字典。"""
        return {
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'category': self.category,
            'stage': self.stage,
            'icon': self.icon,
            'is_builtin': self.is_builtin,
            'is_available': self.is_available(),
        }
