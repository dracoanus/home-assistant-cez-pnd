# CEZ PND Collector

This experimental App wrapper runs the prebuilt Collector service image. It
exposes only the authenticated HTTPS Collector API on the internal Home
Assistant App network. It publishes no host port and contains no Dockerfile.

Release `0.2.3` is the validated synthetic Collector baseline. The unreleased
Phase 3A source adds only an explicitly enabled one-shot CEZ authentication
discovery mode; normal startup remains the unchanged synthetic API. See
[App documentation](DOCS.md), the
[HA OS acceptance plan](../docs/phase2b-collector-ha-app.md), and the
[Phase 3A discovery design](../docs/phase3a-cez-auth-discovery.md).
