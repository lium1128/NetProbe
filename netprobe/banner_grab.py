"""Banner 抓取 — 对非 HTTP 服务获取 banner 指纹信息（含版本提取）。

支持的协议:
- 主动发送探针: MySQL / Redis / MongoDB（已有，深度解析握手包）
- 主动 banner: FTP / SSH / SMTP / POP3 / IMAP / PostgreSQL（补版本正则提取）
返回值含 product/version 字段，用于回填 ports 表（nmap 未识别时兜底）。
"""

import re
import socket
import struct

# 支持 banner 抓取的服务端口和协议
BANNER_PORTS = {
    21: ('ftp', b'220'),
    22: ('ssh', None),
    25: ('smtp', b'220'),
    79: ('finger', None),
    110: ('pop3', b'+OK'),
    143: ('imap', b'* OK'),
    3306: ('mysql', None),
    5432: ('postgresql', None),
    6379: ('redis', None),
    27017: ('mongodb', None),
}

BANNER_TIMEOUT = 5

# ── 版本提取正则（按端口/服务）──────────────────────────
# 每个 pattern: (product 提取正则, version 捕获组序号)
# product 名规范化为大写首字母，version 取第 1 捕获组
VERSION_PATTERNS = {
    'ssh': re.compile(r'SSH-[\d.]+-(\S+?)_([\d.]+p?\d*)', re.IGNORECASE),       # SSH-2.0-OpenSSH_8.9p1 → OpenSSH 8.9p1
    'ftp': re.compile(r'(\S+)\s+(?:ftp|server)\s+v?([\d.]+)', re.IGNORECASE),    # vsFTPd 3.0.3 / ProFTPD 1.3.5
    'smtp': re.compile(r'(\S+)\s+(?:ESMTP|Postfix)\s+([\d.]+)', re.IGNORECASE),  # Postfix 3.4.8 / Exim 4.92
    'pop3': re.compile(r'(\S+)\s+([\d.]+)', re.IGNORECASE),                       # Dovecot pop3 2.3.4
    'imap': re.compile(r'(\S+)\s+([\d.]+)', re.IGNORECASE),                       # Dovecot imap 2.3.4 / Cyrus 3.0
    'postgresql': re.compile(r'PostgreSQL\s+([\d.]+)', re.IGNORECASE),           # 无独立 product，version 即够
}


def grab_banner(ip: str, port: int) -> dict:
    """对指定 IP:端口抓取 banner。

    返回 {'port': int, 'service': str, 'banner': str, 'product': str, 'version': str}
    product/version 可能为空串（无法解析时）。
    """
    service = BANNER_PORTS.get(port, (str(port), None))[0]
    service = service if isinstance(service, str) else str(port)

    banner = ''
    product = ''
    version = ''

    try:
        with socket.create_connection((ip, port), timeout=BANNER_TIMEOUT) as sock:
            # 某些服务需要等待 banner（FTP、SSH、SMTP 会主动发送）
            # MySQL/Redis 等需要发送探针
            if port == 3306:
                # MySQL 握手包
                data = sock.recv(4096)
                banner = _parse_mysql_banner(data)
                product, version = 'MySQL', _extract_mysql_version(data)
            elif port == 6379:
                sock.sendall(b'INFO\r\n')
                data = sock.recv(4096)
                banner = _parse_redis_info(data)
                product, version = 'Redis', _extract_redis_version(data)
            elif port == 27017:
                try:
                    import bson as _bson
                except ImportError:
                    banner = 'MongoDB'
                    product = 'MongoDB'
                    return {'port': port, 'service': service, 'banner': banner, 'product': product, 'version': version}
                ismaster = _bson.BSON.encode({'ismaster': 1, 'helloOk': True})
                header = struct.pack('<iiii', 16 + len(ismaster), 0, 0, 1)
                sock.sendall(header + ismaster)
                data = sock.recv(4096)
                banner = _parse_mongo_info(data)
                product, version = 'MongoDB', _extract_mongo_version(data)
            elif port == 5432:
                # PostgreSQL 需发送启动消息才能拿到错误响应中的版本
                startup = struct.pack('!II', 8, 80877103)  # SSLRequest 探测
                try:
                    sock.sendall(startup)
                    data = sock.recv(4096)
                    text = data.decode('utf-8', errors='replace')
                    banner = text.strip()[:300] if text else ''
                    m = VERSION_PATTERNS['postgresql'].search(text)
                    if m:
                        product, version = 'PostgreSQL', m.group(1)
                except (socket.error, OSError):
                    pass
            else:
                # FTP/SSH/SMTP/POP3/IMAP/Finger 会主动发送 banner
                data = sock.recv(4096)
                if data:
                    banner = data.decode('utf-8', errors='replace').strip()[:500]
                    product, version = _parse_text_banner(service, banner)
    except (socket.timeout, socket.error, OSError):
        pass

    return {'port': port, 'service': service, 'banner': banner, 'product': product, 'version': version}


def grab_banners_for_host(ip: str, open_ports: list[int]) -> list[dict]:
    """对主机的所有开放端口批量抓取 banner。"""
    results = []
    for port in open_ports:
        # 跳过 Web 端口（已由 web_probe 处理）
        if port in (80, 443, 8080, 8443, 8000, 3000, 5000, 9000,
                    8888, 9090, 7001, 8880, 8001, 8002, 10000, 4000, 6000):
            continue
        info = grab_banner(ip, port)
        if info.get('banner'):
            results.append(info)
        elif info.get('product'):
            # 无 banner 文本但有 product/version（如某些探测成功的情况）
            results.append(info)
    return results


def _parse_text_banner(service: str, banner: str) -> tuple[str, str]:
    """从文本 banner 提取 product/version（SSH/FTP/SMTP/POP3/IMAP）。

    返回 (product, version)，无法解析返回 ('', '')。
    """
    if not banner:
        return '', ''
    pat = VERSION_PATTERNS.get(service)
    if not pat:
        return '', ''
    m = pat.search(banner)
    if not m:
        return '', ''
    groups = m.groups()
    if service == 'postgresql':
        return 'PostgreSQL', groups[0]
    # ssh/ftp/smtp/pop3/imap: groups[0]=product, groups[1]=version
    product = groups[0] if len(groups) >= 1 else ''
    version = groups[1] if len(groups) >= 2 else ''
    # 规范化 product 名（OpenSSH → OpenSSH，保持原样即可）
    return product.strip(), version.strip()


def _parse_mysql_banner(data: bytes) -> str:
    """解析 MySQL 握手包中的版本信息。"""
    try:
        if len(data) < 5:
            return ''
        version_end = data.find(b'\0', 5)
        if version_end > 0:
            version = data[5:version_end].decode('utf-8', errors='replace')
            return f'MySQL {version}'
    except Exception:
        pass
    return data.decode('utf-8', errors='replace').strip()[:200]


def _extract_mysql_version(data: bytes) -> str:
    """从 MySQL 握手包提取纯版本号。"""
    try:
        if len(data) < 5:
            return ''
        version_end = data.find(b'\0', 5)
        if version_end > 0:
            return data[5:version_end].decode('utf-8', errors='replace').strip()
    except Exception:
        pass
    return ''


def _parse_redis_info(data: bytes) -> str:
    """解析 Redis INFO 响应。"""
    try:
        text = data.decode('utf-8', errors='replace')
        for line in text.splitlines():
            if line.startswith('redis_version:'):
                return f'Redis {line.split(":")[1].strip()}'
        return 'Redis (version unknown)'
    except Exception:
        return ''


def _extract_redis_version(data: bytes) -> str:
    """从 Redis INFO 提取纯版本号。"""
    try:
        text = data.decode('utf-8', errors='replace')
        for line in text.splitlines():
            if line.startswith('redis_version:'):
                return line.split(":")[1].strip()
    except Exception:
        pass
    return ''


def _parse_mongo_info(data: bytes) -> str:
    """解析 MongoDB ismaster 响应。"""
    try:
        import bson as _bson
        if len(data) < 16:
            return ''
        msg_len = struct.unpack('<i', data[0:4])[0]
        body = data[16:msg_len]
        doc = _bson.BSON(body).decode()
        version = doc.get('version', '')
        if version:
            return f'MongoDB {version}'
        return 'MongoDB'
    except Exception:
        return 'MongoDB'


def _extract_mongo_version(data: bytes) -> str:
    """从 MongoDB ismaster 提取纯版本号。"""
    try:
        import bson as _bson
        if len(data) < 16:
            return ''
        msg_len = struct.unpack('<i', data[0:4])[0]
        body = data[16:msg_len]
        doc = _bson.BSON(body).decode()
        return doc.get('version', '')
    except Exception:
        return ''
