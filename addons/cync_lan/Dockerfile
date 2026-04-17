ARG BUILD_FROM=ghcr.io/home-assistant/base:latest
FROM $BUILD_FROM

# -----------------------------
# Environment
# -----------------------------
ENV \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    CYNC_VERSION="0.1.12" \
    CYNC_TOPIC="cync_lan" \
    CYNC_HASS_TOPIC="homeassistant" \
    CYNC_HASS_STATUS_TOPIC="status" \
    CYNC_HASS_BIRTH_MSG="online" \
    CYNC_HASS_WILL_MSG="offline" \
    CYNC_PORT=23779 \
    CYNC_HOST="0.0.0.0" \
    CYNC_CERT="/root/cync-lan/certs/cert.pem" \
    CYNC_KEY="/root/cync-lan/certs/key.pem" \
    CYNC_DEBUG=0 \
    CYNC_RAW_DEBUG=0 \
    CYNC_MQTT_CONN_DELAY=10 \
    CYNC_CMD_BROADCASTS=2 \
    CYNC_MAX_TCP_CONN=8 \
    CYNC_TCP_WHITELIST=""

WORKDIR /root/cync-lan

# -----------------------------
# System dependencies
# -----------------------------
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-setuptools \
    py3-wheel \
    python3-dev \
    libffi-dev \
    musl-dev \
    libc-dev \
    openssl \
    git \
    build-base \
    cmake

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip

# -----------------------------
# Python dependencies
# -----------------------------
RUN pip install --no-cache-dir \
    Flask \
    pyyaml==6.0.2 \
    requests>=2.32.3 \
    uvloop>=0.21.0 \
    aiomqtt==2.3.0 \
    aiohttp>=3.10.8 \
    fastapi>=0.115.12 \
    uvicorn>=0.34.3 \
    tzlocal>=5.3.1

# -----------------------------
# Clone and install cync-lan
# -----------------------------
RUN git clone -b python https://github.com/baudneo/cync-lan.git /app/cync-lan
RUN cp -r /app/cync-lan/. /root/cync-lan/
RUN pip install /app/cync-lan

# Fix executable (handle both possible paths safely)
RUN chmod +x /app/cync-lan/src/cync_lan/main.py || true
RUN chmod +x /app/cync-lan/src/cync-lan.py || true

# -----------------------------
# Remove build dependencies
# -----------------------------
RUN apk del \
    git \
    build-base \
    cmake \
    python3-dev \
    libffi-dev \
    musl-dev \
    libc-dev \
    && rm -rf /var/cache/apk/*

# -----------------------------
# Generate SSL certs
# -----------------------------
RUN mkdir -p /root/cync-lan/certs \
    && openssl req -x509 -newkey rsa:4096 \
        -keyout /root/cync-lan/certs/key.pem \
        -out /root/cync-lan/certs/cert.pem \
        -subj "/CN=*.xlink.cn" \
        -sha256 -days 3650 -nodes

# -----------------------------
# App layer
# -----------------------------
COPY run.sh /run.sh
RUN chmod +x /run.sh

# Web UI assets
RUN cp -r /app/cync-lan/static/. /root/cync-lan/www/

# Setup config folder
RUN mkdir -p /data/cync-lan

# Create symlink
RUN ln -s /data/cync-lan /root/cync-lan/config

LABEL org.opencontainers.image.authors="baudneo <86508179+baudneo@users.noreply.github.com>"
LABEL org.opencontainers.image.version="v${CYNC_VERSION}"
LABEL org.opencontainers.image.source="https://github.com/baudneo/cync-lan"

CMD ["/run.sh"]