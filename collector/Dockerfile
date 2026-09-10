FROM ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime:0.1.0@sha256:e0fefbfa049a1843ab4ef6711665168445789776bb25ff03c2e318b933f033fc

USER root
COPY --chown=0:0 --chmod=0444 requirements-requests-compatibility.txt /tmp/requirements-requests-compatibility.txt
RUN /opt/collector-venv/bin/pip install --disable-pip-version-check --no-cache-dir --no-deps --only-binary=:all: --requirement /tmp/requirements-requests-compatibility.txt \
    && rm -f /tmp/requirements-requests-compatibility.txt

COPY --chown=0:0 --chmod=0555 collector_service /opt/collector-service/collector_service
COPY --chown=0:0 --chmod=0555 collector_entrypoint.py /opt/collector-service/collector_entrypoint.py

WORKDIR /opt/collector-service

ENTRYPOINT ["/opt/collector-venv/bin/python", "/opt/collector-service/collector_entrypoint.py"]

LABEL \
    org.opencontainers.image.title="CEZ PND Collector service skeleton" \
    org.opencontainers.image.description="Authenticated offline Collector API skeleton" \
    org.opencontainers.image.source="https://github.com/dracoanus/home-assistant-cez-pnd"
