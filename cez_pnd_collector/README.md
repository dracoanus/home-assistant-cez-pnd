# CEZ PND Collector App

This App runs the prebuilt CEZ PND Collector image and exposes its
authenticated HTTPS API only on the internal Home Assistant App network. It
does not publish a host port and contains no App Dockerfile.

The App stores normalized CEZ interval data, performs scheduled synchronization
and keeps CEZ credentials inside its own private configuration. See the
[installation guide](../docs/installation.md),
[configuration guide](../docs/configuration.md), and detailed
[App option reference](DOCS.md).
