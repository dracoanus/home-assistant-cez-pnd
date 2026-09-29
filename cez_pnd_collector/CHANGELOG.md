# Changelog

## 0.3.37

- Added a diagnostic current-day A/B export comparison using metadata-provided idDeviceSet.
- Shadow export results are parsed only in memory and never affect the production dataset.
- Added safe comparison diagnostics for determining whether idDeviceSet affects current-day data freshness.
- No production CEZ request, storage, API, pairing, statistics, or Home Assistant behavior changes.

## 0.3.36

- Added secret-safe diagnostics for CEZ current-day synchronization.
- Added metadata shape, meter-selection and export-context diagnostics.
- Added first and last valid interval timestamps to synchronization diagnostics.
- No synchronization, authentication, parsing, storage, API or security behavior changes.

## 0.3.35

- Added Czech configuration labels and descriptions.
- Added English fallback translations.
- Simplified the default App configuration view.
- Moved diagnostic and legacy settings to optional/advanced configuration.
- Updated managed-pairing and recovery documentation.
- No Collector runtime or security model changes.
