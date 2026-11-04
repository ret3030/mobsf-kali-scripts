# Android Application Penetration Testing

A white-box field guide and Kali toolkit for testing Android applications end to end, organised around the OWASP Mobile Top 10 (2024) and mapped to MASVS / MASTG.

The guide assumes an authorised engagement (signed SOW or rules of engagement) with access to the APK and source. It is non-destructive by design: the goal is to find and evidence defects, not to modify the application or defeat its controls beyond what is needed to observe a vulnerability on a device you control.

## Contents

- `android-pentest-guide.pdf` — the compiled guide.
- `src/` — LaTeX sources (`preamble.tex`, `frontmatter.tex`, `chapters/`).
- `scripts/setup-kali.sh` — install the toolkit on Kali.
- `scripts/android-recon.sh` — read-only static triage of an APK.
- `build.py` — build the PDF with Tectonic.

## Guide structure

| Chapter | Topic | Mobile Top 10 |
|---|---|---|
| 0 | Engagement setup and the Kali lab | preparation |
| 1 | Static analysis: manifest, code, dependencies | M1 M2 M4 M5 M7 M8 M10 |
| 2 | Local data storage | M9 M6 |
| 3 | Dynamic and runtime analysis | M1 M6 M7 |
| 4 | Network and API testing | M5 M3 |
| 5 | Platform and business logic | M3 M4 M6 |
| 6 | Mapping, severity, and reporting | all |

## Quick start

```bash
# install tools on Kali
./scripts/setup-kali.sh

# static triage of an APK (read-only)
./scripts/android-recon.sh target.apk
```

## Building the PDF

Requires [Tectonic](https://tectonic-typesetting.github.io/) and the Cambria + Aptos
fonts in `fonts/` (not committed; copy them in locally). Then:

```bash
python3 build.py
```

## License and use

For use by authorised security professionals only. Testing applications or systems
without written authorisation is illegal in most jurisdictions.
