# ── NetProbe Dockerfile（多阶段构建）──────────────────────────
# 阶段1: 前端构建  阶段2: 运行时（Python + 扫描工具 + Playwright）

# ═══ 阶段 1：前端构建 ════════════════════════════════════════
FROM node:20-alpine AS frontend-builder

WORKDIR /build
# 先拷依赖文件利用层缓存
COPY frontend/package.json frontend/package-lock.json* ./frontend/
RUN cd frontend && npm ci --no-audit --no-fund

# 再拷源码构建
COPY frontend/ ./frontend/
RUN cd frontend && npm run build
# 产物在 /build/frontend/dist


# ═══ 阶段 2：运行时 ══════════════════════════════════════════
FROM python:3.12-slim AS runtime

# 时区（与 APScheduler 一致）
ENV TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# 系统依赖 + 扫描工具
# nmap: 必装（python-nmap 强依赖）；masscan: 端口扫描加速
# libnmap3 不存在，nmap 包已含；git 用于拉 nuclei 模板
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    git \
    curl \
    ca-certificates \
    tzdata \
    && ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python 依赖（先装依赖利用缓存）
COPY server/requirements.txt ./server/requirements.txt
RUN pip install --no-cache-dir -r server/requirements.txt

# Go 工具：subfinder / nuclei（httpx 可选）
# 用预编译二进制避免装 Go 工具链，减小镜像体积
ARG SUBFINDER_VERSION=2.6.7
ARG NUCLEI_VERSION=3.3.7
RUN ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in \
        amd64) GOARCH=linux-amd64 ;; \
        arm64) GOARCH=linux-arm64 ;; \
        *) echo "unsupported arch: $ARCH" && exit 1 ;; \
    esac \
    && curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_${GOARCH}.zip" -o /tmp/sf.zip \
    && cd /tmp && unzip -o sf.zip subfinder && mv subfinder /usr/local/bin/ && chmod +x /usr/local/bin/subfinder && rm -f sf.zip \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${GOARCH}.zip" -o /tmp/nc.zip \
    && cd /tmp && unzip -o nc.zip nuclei && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei && rm -f nc.zip

# Playwright chromium（用于 Web 截图，失败不影响主流程）
RUN playwright install --with-deps chromium || echo "[warn] Playwright chromium 安装失败，截图功能不可用"

# Nuclei 模板（首次拉取，运行时 nuclei 会自动更新）
RUN mkdir -p /root/nuclei-templates && nuclei -update-templates -silent 2>/dev/null || true

# 拷贝项目代码
COPY . .

# 用阶段1的前端构建产物覆盖（后端托管静态文件）
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# 数据目录（volume 挂载点）
RUN mkdir -p /app/data /app/output
VOLUME ["/app/data", "/app/output"]

EXPOSE 8000

# 生产模式启动 uvicorn（无 reload）
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
