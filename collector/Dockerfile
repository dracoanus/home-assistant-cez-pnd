FROM ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime:0.1.0@sha256:e0fefbfa049a1843ab4ef6711665168445789776bb25ff03c2e318b933f033fc

COPY --chown=0:0 --chmod=0555 collector_service /opt/collector-service/collector_service

USER 2000:2000
WORKDIR /opt/collector-service

CMD ["/opt/collector-venv/bin/python", "-m", "collector_service.server"]

LABEL \
    org.opencontainers.image.title="CEZ PND Collector service skeleton" \
    org.opencontainers.image.description="Authenticated offline Collector API skeleton" \
    org.opencontainers.image.source="https://github.com/dracoanus/home-assistant-cez-pnd"
