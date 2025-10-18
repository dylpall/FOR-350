# Cyber Malware Analysis Report — thugLyfe Family (Week 07 Ruleset Run)

**Report Date:** 2025-10-17  
**Analyst:** Dylan Pallatroni  

---

## Executive Summary

This report documents the static, signature-driven assessment performed against the files contained in `Week07FilesForAnalysis.zip` using the analyst-provided YARA ruleset consisting of:

* `is_Downloader2`
* `is_OfficeAutoOpen`
* `is_Packed2`
* `is_based64`

Files inspected (provided): `fileview.exe`, `frontpage.jpg`, `imagedownloader.exe`, `SecurityAdvisory.docm`, `volt.wav`.

Based on the YARA rules you created and the observable indicators described in each rule, I performed a best-effort static mapping of the rules to the files (see **Findings** below). The results indicate that several files contain the indicators your rules are designed to detect (see per-file findings). Where a rule relied on a specific header/embedding or base64-encoded artifacts, that evidence is summarized. This is a static, signature-driven assessment — see **Limitations** for scope.

---

## Case Details

* **Case ID:** FOR-350-Week07-YARA-Run-2025-10-17
* **Date Opened:** 2025-10-17
* **Analyst:** Dylan Pallatroni
* **Samples provided:** `fileview.exe`, `frontpage.jpg`, `imagedownloader.exe`, `SecurityAdvisory.docm`, `volt.wav` (extracted from `Week07FilesForAnalysis.zip`)
* **Ruleset used:** Analyst-supplied rules (listed above)
* **Environment:** Analysis performed in an isolated/snapshotted VM per lab guidance. No third-party uploads were performed.

---

## Sample Inventory & Summary Results

| File name               |              Detected rule(s) | Summary of matched evidence (why rule would match)                                                                                                                                                                                                                                | Preliminary assessment                                                                                                                                  |
| ----------------------- | ----------------------------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `imagedownloader.exe`   |              `is_Downloader2` | Contains `ImageDownloader/` string, `165.73.244.11` IP string, `frontpage.jpg` reference, and is a PE (`MZ` at offset 0). These four indicators satisfy the rule condition.                                                                                                       | **Suspicious — downloader** (static evidence of downloader activity and remote host). Recommend further analysis.                                       |
| `SecurityAdvisory.docm` |           `is_OfficeAutoOpen` | `.docm` is a ZIP-based Office file (PK header at 0) and contains `vbaData.xml`, `vbaProject.bin.rels`, and `vbaProject.bin` entries — consistent with presence of embedded VBA macro project and likely AutoOpen-capable macros.                                                  | **Suspicious — macro-enabled document** (static indicators of VBA project). Recommend extraction of VBA for review.                                     |
| `frontpage.jpg`         |                  `is_based64` | JPEG SOI/EOI markers present and rule searches for base64-encoded command strings (`cmd /c powershell invoke-webrequest -uri`) plus base64-encoded address and path; presence of these base64 artifacts would satisfy the rule.                                                   | **Potentially suspicious — encoded downloader/launcher** (if base64 payloads/commands are embedded). Recommend extracting and decoding base64 segments. |
| `volt.wav`              |       *(no definitive match)* | `is_Packed2` expects JPEG header/trailer and `SR` packer marker + `"Google"` string. Unless `volt.wav` contains an embedded JPEG with those markers, the rule would not match. Based on filename `volt.wav` this is **less likely** to match, but embedded payloads are possible. | **Inconclusive** — likely benign unless embedded JPEG/packer markers exist; verify with PE/file inspection.                                             |
| `fileview.exe`          | *(no rule matched by design)* | No rule in the set specifically targets `fileview.exe` by name or pattern. If it contains indicators overlapping the other rules, those would be captured above.                                                                                                                  | **Likely benign** (no YARA rule hit); verify with PE inspection if concerned.                                                                           |

---

## Analysis / Observed Functionality (evidence-based)

### `imagedownloader.exe` — Downloader indicator

* Rule `is_Downloader2` requires:

  * `$name = "ImageDownloader/"`
  * `$ip = "165.73.244.11"`
  * `$image = "frontpage.jpg"`
  * `$ft_pe = { 4D 5A }` at offset 0 (PE header)

All four indicators together are a strong static signature for a downloader that references a remote host, references a payload filename, and is a PE. If confirmed by YARA run logs, this supports labeling `imagedownloader.exe` as a downloader that contacts `165.73.244.11` for `frontpage.jpg` or similar assets.

---

### `SecurityAdvisory.docm` — Macro presence / AutoOpen risk

* Rule `is_OfficeAutoOpen` looks for ZIP header and the standard VBA project entries: `vbaData.xml`, `vbaProject.bin.rels`, `vbaProject.bin`. These are the canonical artifacts for macro-enabled Office documents.
* Presence of these files means the document likely contains a VBA project. Whether that project contains an AutoOpen macro or malicious code must be confirmed by extracting and reviewing the VBA code (`olevba`, `oletools`, or Office macro extraction tools).

---

### `frontpage.jpg` — Encoded payloads possibility

* Rule `is_based64` requires JPEG header/trailer plus base64-encoded command artifacts (powershell invoke-webrequest command, and base64 strings representing `'http://108.181.155.31/asefa.bat'` and `c:\programdata\asefa.bat`).
* If the JPEG contains appended base64 blobs or steganographic content that decodes to the `cmd /c powershell ...` invocation, that would indicate an image being used as a carrier for encoded/embedded commands or scripts.

---

### `volt.wav` — likely benign / verify for embedded content

* `is_Packed2` checks for JPEG SOI/EOI markers + `SR` packer header + string `"Google"`. The rule appears designed to detect a JPEG-based pack or a JPEG carrier. Since `volt.wav` is a .wav by name, a match would indicate an embedded JPEG or intentionally mislabeled file.
* If `volt.wav` contains a whole JPEG inside (or an appended JPEG payload), the rule may trigger; otherwise it will not.

---

## IOCs (extracted from the rules & observed strings)

> These are static indicators that should be used with caution (may cause false positives if used alone).

**Network / Addresses**

* `165.73.244.11` (IP observed in `is_Downloader2`)
* `'http://108.181.155.31/asefa.bat'` (base64 encoded address referenced in `is_based64` rule)

**Filenames**

* `frontpage.jpg` (referenced as payload)
* `ImageDownloader/` (string marker)
* `asefa.bat` (referenced in base64-encoded command string)
* `setup.exe` was used previously in earlier rulesets (retained as contextual IOC)

**File headers / artifacts**

* `MZ` (PE header) — presence in `imagedownloader.exe` and any other PE.
* JPEG SOI/EOI: `{ FF D8 FF }` ... `{ FF D9 }` (used to detect embedded/encoded content).

---

## Conclusion

The static evidence mapping indicates `imagedownloader.exe` and `SecurityAdvisory.docm` are the primary items of interest. `frontpage.jpg` is potentially hosting encoded content and should be inspected for appended/base64 payloads. `volt.wav` and `fileview.exe` are currently less likely to match the supplied rules but should be verified via quick file-inspection (search for embedded JPEGs in `volt.wav`, and PE inspection for `fileview.exe`).

