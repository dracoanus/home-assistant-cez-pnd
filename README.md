# Secure CEZ PND integration for Home Assistant

This project is designing a secure integration for retrieving CEZ PND
measurement data in Home Assistant. The planned architecture separates a
credential-holding Collector App from a minimal Home Assistant custom
integration that handles sensors and statistics.

Current status: **design and feasibility verification**. The integration is
not yet implemented or production ready. Phase 2A-1 runtime feasibility
verification is in progress; Phase 2A-2 has not started.

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

## License

Licensed under the [MIT License](LICENSE).
