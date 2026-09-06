FROM ghcr.io/home-assistant/base:3.24@sha256:93ef607824e3f27e868f11b10938283a98bf880ed57bcf8eaa81c6c2d521f6f5

ARG BUILD_VERSION=0.0.1
ARG BUILD_ARCH=amd64

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

ENV \
    HOME=/home/phase2a \
    PATH=/opt/phase2a-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SE_AVOID_BROWSER_DOWNLOAD=true \
    SE_AVOID_STATS=true \
    SE_OFFLINE=true

COPY requirements.lock /tmp/requirements.lock

RUN apk add --no-cache \
        chromium=152.0.7977.82-r0 \
        chromium-chromedriver=152.0.7977.82-r0 \
        python3 \
        py3-pip \
    && python3 -m venv /opt/phase2a-venv \
    && /opt/phase2a-venv/bin/pip install \
        --disable-pip-version-check \
        --index-url https://pypi.org/simple \
        --no-deps \
        --only-binary=:all: \
        --require-hashes \
        --requirement /tmp/requirements.lock \
    && addgroup -g 2000 -S phase2a \
    && adduser -u 2000 -S -D -H -h /home/phase2a -G phase2a phase2a \
    && install -d -o 0 -g 0 -m 0555 /home/phase2a /opt/phase2a \
    && rm -f /tmp/requirements.lock \
    && apk --no-network --repositories-file /dev/null info -e \
        "chromium=152.0.7977.82-r0" \
        "chromium-chromedriver=152.0.7977.82-r0"

COPY --chown=0:0 runtime_probe.py /opt/phase2a/runtime_probe.py

RUN chmod 0555 /opt/phase2a/runtime_probe.py \
    && find /opt/phase2a-venv -type d -exec chmod a-w {} + \
    && find /opt/phase2a-venv -type f -exec chmod a-w {} +

USER 2000:2000
WORKDIR /opt/phase2a

ENTRYPOINT []
CMD ["/opt/phase2a-venv/bin/python", "/opt/phase2a/runtime_probe.py"]

LABEL \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.type="app" \
    io.hass.arch="${BUILD_ARCH}" \
    org.opencontainers.image.title="Disposable CEZ PND Phase 2A runtime probe" \
    org.opencontainers.image.description="Offline-only experimental artifact; not production Collector code"
