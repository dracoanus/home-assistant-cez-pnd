FROM python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

ARG DEBIAN_SNAPSHOT=20260907T000000Z
ARG CHROMIUM_VERSION=152.0.7977.82-1~deb12u1
ARG PASSWD_VERSION=1:4.13+dfsg1-1+deb12u2
ARG TINI_VERSION=0.19.0-1+b3

ENV \
    HOME=/tmp/collector-home \
    PATH=/opt/collector-venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SE_AVOID_BROWSER_DOWNLOAD=true \
    SE_AVOID_STATS=true \
    SE_OFFLINE=true

# Freeze Debian inputs before installing the expensive browser layer. Source
# changes below this layer do not reinstall Chromium or ChromeDriver.
RUN printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/* \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      chromium="${CHROMIUM_VERSION}" \
      chromium-driver="${CHROMIUM_VERSION}" \
      chromium-sandbox="${CHROMIUM_VERSION}" \
      passwd="${PASSWD_VERSION}" \
      tini="${TINI_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# Keep cheap package and executable validation outside the expensive APT layer.
# A validation-only edit can then reuse the installed browser layer.
RUN command -v /usr/sbin/groupadd >/dev/null \
    && command -v /usr/sbin/useradd >/dev/null \
    && command -v /usr/bin/install >/dev/null \
    && command -v /usr/bin/stat >/dev/null \
    && command -v /usr/bin/dpkg-query >/dev/null \
    && command -v /bin/false >/dev/null \
    && command -v /usr/local/bin/python >/dev/null \
    && command -v /usr/bin/tini >/dev/null \
    && command -v /usr/bin/chromium >/dev/null \
    && command -v /usr/bin/chromedriver >/dev/null \
    && test "$(dpkg-query -W -f='${db:Status-Status}' chromium)" = "installed" \
    && test "$(dpkg-query -W -f='${Version}' chromium)" = "${CHROMIUM_VERSION}" \
    && test "$(dpkg-query -W -f='${db:Status-Status}' chromium-driver)" = "installed" \
    && test "$(dpkg-query -W -f='${Version}' chromium-driver)" = "${CHROMIUM_VERSION}" \
    && test "$(dpkg-query -W -f='${db:Status-Status}' chromium-sandbox)" = "installed" \
    && test "$(dpkg-query -W -f='${Version}' chromium-sandbox)" = "${CHROMIUM_VERSION}" \
    && test "$(stat -c '%U:%G:%a' /usr/lib/chromium/chrome-sandbox)" = "root:root:4755" \
    && test "$(dpkg-query -W -f='${db:Status-Status}' passwd)" = "installed" \
    && test "$(dpkg-query -W -f='${Version}' passwd)" = "${PASSWD_VERSION}" \
    && test "$(dpkg-query -W -f='${db:Status-Status}' tini)" = "installed" \
    && test "$(dpkg-query -W -f='${Version}' tini)" = "${TINI_VERSION}"

COPY requirements.lock /tmp/requirements.lock

RUN /usr/local/bin/python -m venv /opt/collector-venv \
    && test -x /opt/collector-venv/bin/pip \
    && /opt/collector-venv/bin/pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --no-deps \
      --only-binary=:all: \
      --require-hashes \
      --requirement /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock

# User creation is cheap and independent of the hash-locked Python layer.
RUN /usr/sbin/groupadd --gid 2000 collector \
    && /usr/sbin/useradd --uid 2000 --gid 2000 --no-create-home \
      --home-dir /nonexistent --shell /bin/false collector \
    && /usr/bin/install -d -o 0 -g 0 -m 0555 /opt/collector

COPY --chown=0:0 smoke_test.py /opt/collector/smoke_test.py

RUN chmod 0555 /opt/collector/smoke_test.py

USER 2000:2000
WORKDIR /opt/collector

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/collector-venv/bin/python", "/opt/collector/smoke_test.py"]

LABEL \
    org.opencontainers.image.title="CEZ PND collector runtime experiment" \
    org.opencontainers.image.description="Minimal offline Chromium/Selenium feasibility runtime" \
    org.opencontainers.image.source="https://github.com/dracoanus/home-assistant-cez-pnd"
