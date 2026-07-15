# Google Mobile Services (GMS) Certification Checker

A comprehensive GMS certification detection toolkit for Android devices.
Identifies GMS certification status, detects non-certified/forked devices,
manages a device catalog, and generates HTML reports.

## Features

- **GMS Checker** — `src/gms_checker.py`
  Detects GMS components (Play Store, Play Services, GSF, etc.),
  identifies certification gaps, and detects suspicious packages.

- **CTS Profile Analyzer** — `src/cts_profile.py`
  Analyzes CTS compatibility profiles, maps requirements to certification
  status, and generates compatibility verdicts.

- **Device Catalog** — `src/device_catalog.py`
  SQLite-backed catalog of known GMS-certified and non-certified devices
  with certification dates and hardware info.

- **HTML Report Generator** — `src/report_generator.py`
  Generates visual HTML reports for GMS certification results.

- **Known Devices Database** — `data/known_devices.json`
  Reference database of certified and non-certified device models.

## Quick Start

```bash
# Check GMS certification status
python -m src.gms_checker --json

# Quick certification check
python -m src.device_catalog check --manufacturer Samsung --model "Galaxy S23"

# Generate HTML report
python -m src.gms_checker --json > result.json
python -m src.report_generator --input-json result.json --output report.html

# Analyze CTS compatibility
python -m src.cts_profile --json

# Lookup device in catalog
python -m src.device_catalog lookup --manufacturer Google
python -m src.device_catalog report
```

## GMS Certification Status

| Status | Description |
|---|---|
| CERTIFIED | Official GMS certified device |
| LICENSEE | Licensed but has missing optional components |
| MICROG | MicroG GMS replacement (not certified) |
| FORKED | Forked Android (Amazon Fire, etc.) |
| AOSP_ONLY | Stock AOSP without GMS |
| UNCERTIFIED | Not certified, no GMS |

## GMS Core Components

For full certification, these components must be present:

| Package | Name | Critical |
|---|---|---|
| com.android.vending | Play Store | ✅ |
| com.google.android.gms | Play Services | ✅ |
| com.google.android.gsf | Google Services Framework | ✅ |
| com.google.android.gms.location | Location | ❌ |
| com.google.android.gms.ads | Ads | ❌ |
| com.google.android.gms.backup | Backup | ❌ |

## Contact & Support

- **Website:** [qtphone.com](https://qtphone.com)
- **GitHub Issues:** Open an issue in this repository
- **Email:** contact@qtphone.com

## License

MIT License
