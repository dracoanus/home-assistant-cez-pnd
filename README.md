# Secure CEZ PND integration for Home Assistant

This project is designing a secure integration for retrieving CEZ PND
measurement data in Home Assistant. The planned architecture separates a
credential-holding Collector App from a minimal Home Assistant custom
integration that handles sensors and statistics.

Current status: **runtime feasibility and the synthetic Collector 0.2.3 API
gate passed; the first Home Assistant custom-integration milestone is under
local review**. The Debian Collector Runtime Gate passed on the actual HA OS
amd64 target. The production CEZ collection flow is not implemented and the
project is not production ready.

## Experimental runtime gate

The existing **CEZ PND Collector Runtime Gate** App is retained as historical
runtime evidence. The **CEZ PND Collector** App uses a prebuilt Collector
service image and synthetic offline data only. Versions `0.2.0` through
`0.2.2` retain their immutable deployment evidence. Collector `0.2.3` uses
the Supervisor v1 self-info route supported by the validated target and
exposes only its authenticated synthetic API.

To add this repository in Home Assistant, open **Settings -> Apps -> App Store
-> Repositories** and add:

`https://github.com/dracoanus/home-assistant-cez-pnd`

The App references the public prebuilt image repository
`ghcr.io/dracoanus/home-assistant-cez-pnd-collector`; Home Assistant does not
build Chromium or Python during App installation.

## Documentation

- [Phase 1 analysis](docs/phase1-analysis.md)
- [Authoritative project specification](docs/project-specification.md)
- [Collector API contract](docs/collector-api-contract.md)
- [Phase 2B Collector offline validation](docs/phase2b-collector-service-validation.md)
- [Phase 2B Collector App and HA OS gate](docs/phase2b-collector-ha-app.md)
- [Phase 2B Home Assistant integration](docs/phase2b-ha-integration.md)

## License

Licensed under the [MIT License](LICENSE).
