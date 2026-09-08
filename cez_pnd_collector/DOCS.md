# CEZ PND Collector App 0.2.1

This is an **experimental, offline deployment-validation release candidate**.
It serves synthetic data only. It does not contact CEZ, accept CEZ
credentials, or run browser automation.

Before starting the App, provide:

- the opaque synthetic meter ID;
- the lowercase SHA-256 verifier of a separately retained, random bearer
  token containing at least 256 bits of entropy;
- a base64-encoded PEM TLS certificate;
- the matching base64-encoded PEM TLS private key.

The plaintext bearer token must be supplied only to the validation client and,
later, to the limited Home Assistant integration. It must not be entered in
the App options, logs, command line, repository, or image. The TLS certificate
must be valid for the App's Supervisor-assigned internal DNS hostname. The
validation client must trust the issuing private CA or an explicitly reviewed
certificate pin; disabling TLS verification is forbidden.

The service reads its own Supervisor-managed options through the authenticated
v2 `/v2/apps/self/info` endpoint because the non-root UID 2000 process cannot
assume direct access to the Supervisor-owned mode-0600 `/data/options.json`.
Release `0.2.0` omitted the `/v2` prefix and failed closed before HTTPS startup;
`0.2.1` changes only this endpoint. TLS PEM material is decoded into
UID-2000-owned mode-0600 files on `/tmp`, loaded into OpenSSL, and immediately
unlinked. The App enables Supervisor's `/tmp` tmpfs.

This bootstrap is limited to HA OS deployment validation. Production pairing,
automatic certificate issuance/renewal, token transfer to Home Assistant Core,
rotation UX, backup treatment, and writable `/data` ownership are **OPEN /
NEEDS VERIFICATION**. See the
[complete validation plan](../docs/phase2b-collector-ha-app.md).
