# Secure CEZ PND integration for Home Assistant

This project is designing a secure integration for retrieving CEZ PND
measurement data in Home Assistant. The planned architecture separates a
credential-holding Collector App from a minimal Home Assistant custom
integration that handles sensors and statistics.

Current status: **runtime feasibility passed; Collector foundation in review**.
The Debian Collector Runtime Gate passed on the actual HA OS amd64 target. The
production CEZ collection flow and Home Assistant integration are not yet
implemented or production ready.

## Experimental runtime gate

The existing **CEZ PND Collector Runtime Gate** App tests the prebuilt Collector
runtime offline. It does not implement CEZ access or authentication.

To add this repository in Home Assistant, open **Settings -> Apps -> App Store
-> Repositories** and add:

`https://github.com/dracoanus/home-assistant-cez-pnd`

The App uses the public prebuilt image
`ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime:0.1.0`; Home
Assistant does not build Chromium or Python during App installation.
## Documentation

- [Phase 1 analysis](docs/phase1-analysis.md)
- [Authoritative project specification](docs/project-specification.md)
- [Collector API contract](docs/collector-api-contract.md)
- [Phase 2B Collector offline validation](docs/phase2b-collector-service-validation.md)

## License

Licensed under the [MIT License](LICENSE).
