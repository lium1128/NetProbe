"""插件注册中心 — 管理插件的注册、发现和调用。

功能:
  - 注册内置插件（builtin.py 里声明）
  - 自动发现外部插件（data/plugins/ 目录下的 .py 文件）
  - 按阶段过滤启用的插件
  - 统一调用入口（带异常捕获和进度输出）
  - 插件启用状态持久化（data/plugin_states.json）
"""
import importlib
import json
import os
import pkgutil
import time
from pathlib import Path

from .base import Plugin


# 全局插件注册表: name → Plugin 实例
_registry: dict[str, Plugin] = {}
# 启用状态: name → bool
_states: dict[str, bool] = {}
_states_loaded = False

_STATES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'data', 'plugin_states.json'
)


def _load_states():
    """从磁盘加载插件启用状态。"""
    global _states, _states_loaded
    if _states_loaded:
        return
    try:
        if os.path.exists(_STATES_PATH):
            with open(_STATES_PATH, encoding='utf-8') as f:
                _states = json.load(f)
    except (json.JSONDecodeError, OSError):
        _states = {}
    _states_loaded = True


def _save_states():
    """保存插件启用状态到磁盘。"""
    try:
        os.makedirs(os.path.dirname(_STATES_PATH), exist_ok=True)
        with open(_STATES_PATH, 'w', encoding='utf-8') as f:
            json.dump(_states, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def register(plugin_cls):
    """注册一个插件（可以是类或实例）。

    用法:
        @register
        class MyPlugin(Plugin): ...

        或

        register(MyPlugin())
    """
    # 如果是类而非实例，先实例化
    if isinstance(plugin_cls, type):
        plugin = plugin_cls()
    else:
        plugin = plugin_cls
    if not plugin.name:
        raise ValueError(f'插件 {plugin.__class__.__name__} 缺少 name 属性')
    _registry[plugin.name] = plugin
    return plugin_cls  # 装饰器返回原类


def unregister(name: str):
    """注销插件。"""
    _registry.pop(name, None)


def get_all_plugins() -> list[Plugin]:
    """返回所有已注册的插件列表。"""
    _ensure_loaded()
    return sorted(_registry.values(), key=lambda p: (p.category, p.name))


def get_plugin(name: str) -> Plugin | None:
    """按名称获取插件。"""
    _ensure_loaded()
    return _registry.get(name)


def is_enabled(name: str) -> bool:
    """检查插件是否启用。

    默认启用（未在 _states 中记录的插件返回 True）。
    """
    _load_states()
    return _states.get(name, True)


def set_enabled(name: str, enabled: bool):
    """设置插件启用状态并持久化。"""
    _load_states()
    _states[name] = enabled
    _save_states()


def get_enabled_plugins_for_stage(stage: str, options: dict | None = None) -> list[Plugin]:
    """返回指定阶段下所有已启用的插件。

    参数:
        stage: 阶段名（vuln / web / sensitive 等）
        options: 扫描配置（暂未使用，预留）
    """
    _ensure_loaded()
    return [
        p for p in _registry.values()
        if p.stage == stage and is_enabled(p.name) and p.is_available()
    ]


def run_plugin(plugin: Plugin, hosts: list[dict], options: dict,
               emit=None, show_progress: bool = True) -> int:
    """统一调用入口 — 执行插件并捕获异常。

    返回: 发现数（异常返回 0）。
    """
    if show_progress and emit:
        emit('progress', text=f'  · {plugin.display_name} ...')

    t0 = time.time()
    try:
        count = plugin.run(hosts, options, emit)
    except Exception as e:
        if emit:
            emit('progress', text=f'    {plugin.display_name} 失败（不影响主流程）: {e}')
        count = 0

    elapsed = time.time() - t0
    if show_progress and emit:
        if count:
            emit('progress', text=f'    ✓ {plugin.display_name} 完成: {count} 个发现 ({elapsed:.1f}s)')
        else:
            emit('progress', text=f'    ✓ {plugin.display_name} 完成: 无发现 ({elapsed:.1f}s)')

    return count or 0


def run_plugins_for_stage(stage: str, hosts: list[dict], options: dict, emit=None) -> int:
    """执行某个阶段的所有已启用插件。

    返回: 总发现数。
    """
    plugins = get_enabled_plugins_for_stage(stage, options)
    total = 0
    for plugin in plugins:
        total += run_plugin(plugin, hosts, options, emit)
    return total


def _ensure_loaded():
    """确保内置插件和外部插件已加载。"""
    global _loaded
    if getattr(_ensure_loaded, '_loaded', False):
        return
    _ensure_loaded._loaded = True

    # 加载内置插件
    try:
        from . import builtin  # noqa: triggers registration
    except ImportError:
        pass

    # 自动发现外部插件（data/plugins/*.py）
    _discover_external_plugins()


def _discover_external_plugins():
    """从 data/plugins/ 目录发现用户自定义插件。"""
    external_dir = Path(_STATES_PATH).parent / 'plugins'
    if not external_dir.exists():
        return

    import sys
    for py_file in external_dir.glob('*.py'):
        if py_file.name.startswith('_'):
            continue
        module_name = f'_external_plugin_{py_file.stem}'
        try:
            # 动态加载模块
            import importlib.util
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                # 查找模块中的 Plugin 子类并注册
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type)
                            and issubclass(attr, Plugin)
                            and attr is not Plugin
                            and not attr.is_builtin):
                        instance = attr()
                        instance.is_builtin = False
                        register(instance)
        except Exception:
            pass  # 外部插件加载失败不影响主流程


def list_plugins_info() -> list[dict]:
    """返回所有插件的信息（前端展示用）。"""
    return [
        {**p.to_dict(), 'enabled': is_enabled(p.name)}
        for p in get_all_plugins()
    ]
