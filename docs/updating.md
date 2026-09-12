# Updating

Collector App and Home Assistant integration have independent versions.

## Collector App

1. Update **CEZ PND Collector** in the Home Assistant App Store.
2. Review configuration notes before starting the updated App.
3. Confirm safe startup and synchronization events.

Collector options and normalized data are intended to remain available across
ordinary updates. Keep Home Assistant backups; do not assume a rollback
preserves data from a newer schema without checking release notes.

## HACS integration

1. Update the integration in HACS.
2. Restart Home Assistant. Python integration code remains loaded until restart.
3. Check the integration and Energy Dashboard after restart.

## Rollback

Use a new release rather than rewriting public tags. Before rollback, record
versions and create a Home Assistant backup. Do not delete the Collector
dataset merely to resolve an update issue; inspect safe logs first.
