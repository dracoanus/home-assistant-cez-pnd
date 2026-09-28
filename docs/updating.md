# Updating

Collector App and Home Assistant integration have independent versions.

## Collector App

1. Review the App changelog and release notes. Record the installed Collector
   and integration versions.
2. Create or retain a usable Home Assistant backup before a significant
   upgrade.
3. Update **CEZ PND Collector** in the Home Assistant App Store.
4. Confirm that the App starts, managed identity remains available and a
   scheduled synchronization completes without a new fixed error code.

Collector options and normalized data are intended to remain available across
ordinary updates. Keep Home Assistant backups; do not assume a rollback
preserves data from a newer schema without checking release notes.

## HACS integration

1. Review the integration release notes, then update it through HACS.
2. Restart Home Assistant when HACS requests it. Python integration code
   remains loaded until restart.
3. Check the integration entry, entities, Recorder statistics and Energy
   Dashboard after restart.

## Rollback

Published tags and container images must never be moved or overwritten. Before
rollback, record both installed versions and preserve a Home Assistant backup.
Use the supported App/HACS version controls or restore a known compatible
backup when a data or configuration migration requires it.

Do not delete `/data/cez-pnd-dataset/cez-pnd.sqlite3` as a first troubleshooting
step. It contains the normalized history and synchronization checkpoints.
Inspect safe event codes and release notes first; restore the dataset only as
part of a deliberate backup recovery procedure.
