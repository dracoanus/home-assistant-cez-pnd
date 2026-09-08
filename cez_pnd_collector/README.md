# CEZ PND Collector

This experimental App wrapper runs the prebuilt Collector service image. It
exposes only the authenticated HTTPS Collector API on the internal Home
Assistant App network. It publishes no host port and contains no Dockerfile.

Version `0.2.1` is a narrowly scoped hotfix candidate for the Supervisor v2
self-info endpoint. It does not alter the immutable `0.2.0` release or publish
the corresponding `0.2.1` GHCR image. See [App documentation](DOCS.md) and the
[HA OS acceptance plan](../docs/phase2b-collector-ha-app.md).
