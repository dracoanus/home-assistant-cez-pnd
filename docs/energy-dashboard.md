# Energy Dashboard

The integration writes two Recorder external statistics:

| Energy Dashboard purpose | Statistic ID | Source |
| --- | --- | --- |
| Grid consumption | `cez_pnd:grid_import_energy` | CEZ billing-meter historical import energy |
| Return to grid | `cez_pnd:grid_export_energy` | CEZ billing-meter historical export energy |

In the Energy Dashboard, select the matching CEZ PND grid import/export
statistics where Home Assistant offers external energy statistics. Their values
are historical meter energy, not instantaneous power.

## Current-day delay is expected

CEZ publishes quarter-hour data with delay. Intervals not yet published remain
`MISSING`; they are not interpreted as zero consumption or zero export. Home
Assistant writes an hourly statistic only after all four valid quarter-hour
intervals for that hour are present. An incomplete current hour is therefore
intentionally absent until CEZ publishes the remaining intervals.

Later Collector revisions reconcile new values and corrections automatically.
The data timestamp always indicates the latest genuinely valid CEZ interval,
not a future missing interval.

## kW source profiles

CEZ PND 15-minute profile values behave as quarter-hour average power. For a
`kW` profile the Collector converts each value using
`energy_kwh = value_kw × 0.25`. This has been checked against CEZ's 60-minute
view and is not a Home Assistant estimate.

## Optional real-time power

An inverter integration, for example GoodWe, may provide real-time power, PV
generation or battery data. It is optional and independent. CEZ PND remains
the authoritative historical grid-energy source for this project.
