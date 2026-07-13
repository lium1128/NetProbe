"""NetProbe 插件系统 — 可热插拔的检测模块。

插件类型:
  - vuln: 漏洞/安全检测（结果追加到 host['vulnerabilities']）
  - recon: 侦察/信息收集（结果写入 host['_xxx_findings']）
  - info: 信息展示（纯展示数据）

内置插件在 builtin.py 注册，用户自定义插件放在 data/plugins/ 目录。
"""
