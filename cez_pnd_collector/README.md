# CEZ PND Collector

This experimental App wrapper runs the prebuilt Collector service image. It
exposes only the authenticated HTTPS Collector API on the internal Home
Assistant App network. It publishes no host port and contains no Dockerfile.

Version `0.2.0` is a prepared release candidate. This change does not publish
the corresponding immutable GHCR image; that image must exist before install.
See [App documentation](DOCS.md) and the
[HA OS acceptance plan](../docs/phase2b-collector-ha-app.md).
