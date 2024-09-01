FROM python:3.12.2-slim-bookworm as final

#ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CYNC_VERSION=v0.0.1

WORKDIR /root/cync-lan

RUN set -x \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends \
        openssl git build-essential cmake \
    && pip install --no-cache-dir \
        setuptools>=69.2.0 wheel>=0.41.2 \
        pyyaml>=6.0.1 requests>=2.31.0 uvloop>=0.19.0 \
        git+https://github.com/Yakifo/amqtt.git \
      && DEBIAN_FRONTEND=noninteractive apt-get remove -yq git build-essential cmake \
    && DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq \
    && DEBIAN_FRONTEND=noninteractive apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN set -x \
    && mkdir -p /root/cync-lan/certs \
    && openssl req -x509 -newkey rsa:4096 \
        -keyout '/root/cync-lan/certs/key.pem' -out '/root/cync-lan/certs/cert.pem' \
        -subj '/CN=*.xlink.cn' -sha256 -days 3650 -nodes

COPY ./src/cync-lan.py /root/cync-lan


VOLUME /root/cync-lan/config
EXPOSE 23779

ENV CYNC_MQTT_URL = "mqtt://homeassistant.local:1883" \
    CYNC_PORT = 23779 \
    CYNC_HOST = "0.0.0.0" \
    CYNC_CERT = "/root/cync-lan/certs/cert.pem" \
    CYNC_KEY = "/root/cync-lan/certs/key.pem" \
    CYNC_DEBUG = 0 \
    CYNC_RAW_DEBUG = 0 \
    CYNC_TOPIC = "cync_lan" \
    CYNC_HASS_TOPIC = "homeassistant" \
    CYNC_MESH_CHECK = 30

LABEL org.opencontainers.image.authors="baudneo <86508179+baudneo@users.noreply.github.com>"
LABEL org.opencontainers.image.version="${CYNC_VERSION}"
LABEL org.opencontainers.image.source="https://github.com/baudneo/cync-lan"
LABEL org.opencontainers.image.description="Local control for Cync by GE BT/Wi-Fi devices"

CMD ["python3", "/root/cync-lan/cync-lan.py", "run", "/root/cync-lan/config/cync_mesh.yaml"]
