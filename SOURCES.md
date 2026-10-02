# Driver collection sources — catalog

Thirty-four driver-collection sources tested empirically on **2026-10-01** across two research passes:

- **First pass (16 sources, 387 drivers)** — full per-source notes with pinned-hash artifacts, limitations and integration guidance.
- **Second pass (18 sources, 64 drivers)** — follow-up discovery under `E:\temp\additional-driver-sources\`; lighter detail per source (no per-artifact SHA-256 inventory yet) but same static-only methodology.

Working prototypes of first-pass collectors live outside this repo at `E:\temp\<source>-driver-test\`. Second-pass collectors share `E:\temp\driver-source-tools\discover_*.py` with results in `E:\temp\additional-driver-sources\verified-sources.json`. This file is the lasting catalog; those directories are the implementation reference that a future `pipeline/collectors/<source>.py` can port from.

## Index

| Source | Role | Drivers recovered | Signed `/kp` |
|---|---|---:|---:|
| [Microsoft Update Catalog](#microsoft-update-catalog) | First-party CAB index | 1 | 1 |
| [Dell](#dell) | OEM | 57 | 57 |
| [HP](#hp) | OEM | 158 | 155 |
| [Lenovo](#lenovo) | OEM | 4 | 4 |
| [Intel](#intel) | Component vendor | 68 | 68 |
| [CPU-Z](#cpu-z) | Monitoring utility (BYOVD candidate) | 3 | 2 |
| [HWMonitor](#hwmonitor) | Monitoring utility (BYOVD candidate) | 3 | 2 |
| [HWiNFO](#hwinfo) | Monitoring utility (BYOVD candidate) | 1 | 1 |
| [GIGABYTE](#gigabyte) | OEM utility (BYOVD candidate) | 9 | 3 |
| [MSI Afterburner](#msi-afterburner) | Tuning utility (confirmed BYOVD) | 6 | 0 |
| [CORSAIR](#corsair) | Peripheral vendor | 4 | 0 |
| [Microsoft Surface](#microsoft-surface) | First-party OEM | 36 | 35 |
| [VirtIO Windows](#virtio-windows) | Virtualization | 26 | 26 |
| [WinDivert](#windivert) | Open-source project | 2 | 0 |
| [TousLesDrivers](#touslesdrivers) | Discovery index | 8 | 8 |
| [LOLDrivers](#loldrivers) | Reference set (not a source) | 1 | 1 |
| **Second pass:** | | | |
| [Dokany](#dokany) | Userland FS driver project | 1 | 1 |
| [Focusrite](#focusrite) | Audio peripheral vendor | 4 | 0 |
| [ImDisk / LTR Data](#imdisk--ltr-data) | Virtual disk / image mount driver | 5 | 5 |
| [libusb-win32](#libusb-win32) | USB generic driver | 3 | 0 |
| [Npcap](#npcap) | Network capture driver | 1 | 1 |
| [OpenVPN](#openvpn) | VPN tunnel driver | 2 | 2 |
| [PassMark OSFMount (legacy)](#passmark-osfmount-legacy) | Virtual disk / image mount driver | 2 | 0 |
| [Prolific](#prolific) | USB-serial component vendor | 3 | 3 |
| [Samsung NVMe](#samsung-nvme) | Component vendor (storage) | 8 | 6 |
| [Microsoft Sysinternals](#microsoft-sysinternals) | First-party admin tooling | 3 | 3 |
| [UsbDk](#usbdk) | USB filter driver | 5 | 0 |
| [USBPcap](#usbpcap) | USB capture driver | 1 | 0 |
| [VeraCrypt](#veracrypt) | Full-disk encryption driver | 1 | 1 |
| [Oracle VirtualBox](#oracle-virtualbox) | Virtualization | 12 | 10 |
| [vJoy](#vjoy) | Virtual HID / joystick driver | 2 | 0 |
| [WinBtrfs](#winbtrfs) | Filesystem driver | 4 | 0 |
| [WinFsp](#winfsp) | Userland FS driver project | 3 | 3 |
| [Wintun](#wintun) | Modern tunnel driver | 4 | 3 |

**Total unique drivers across sources (within-source dedup): 451** (387 from the first pass + 64 from the second). Cross-source deduplication is the index pipeline's job — the same SHA-256 appearing in multiple source folders is expected.

## Scope and limits

- All downloads were static. **No vendor installer or application was executed. No driver was loaded.**
- Counts are deduplicated by SHA-256 within each source only.
- URLs and signing decisions can change. The SHA-256s recorded here are anchors for 2026-10-01, not perpetual pins.
- Dell / HP / Lenovo tested one WinPE pack family each, not the full per-model library.
- LOLDrivers is reference data for the L3 clone-detection pass, not a collection source. Malicious entries explicitly excluded.
- TousLesDrivers is a discovery index; the actual download in the test came from NVIDIA, following TLD's own link graph.

---

## Microsoft Update Catalog

**Role:** First-party CAB index, signed-WHQL baseline.
**Prototype:** `E:\temp\catalog-driver-test\`.

Baseline source of WHQL-signed drivers. Low volume per query but official and stable. Useful as a sanity reference — drivers from here should always pass L0 and have clean L1 signals; a divergence suggests pipeline bugs rather than source noise.

**Method:** Browser search on `catalog.update.microsoft.com` → download Microsoft-hosted CAB → `expand.exe` or 7-Zip. The prototype uses Playwright/Chromium for the search step; underlying CDN is `catalog.s.download.windowsupdate.com`.

**Pinned artifact:**
`https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2026/04/680990a5-1908-4a37-9520-e6d70bf34a2d_c37c679071e1ea1a64bcfed1c89b914d3fcdce3d.cab`
SHA-256 `4b3258ffe6c8bf7bf9271cf724a1fbaad530bb743bbd54414730bd769f47d0ca`.

**Notable:** `rtwlane711.sys` (Realtek wireless). **Signature:** 1 / 1 `/kp`.

**Limitations:** First-results-page bound (`--max-results 1`); search is HTML/JS, needs headless browser.

**Integration notes:** Keep the headless-browser dependency isolated. Rate-limit politely — search page is throttle-sensitive. Cache catalog search results by (query, date).

---

## Dell

**Role:** OEM, high-volume signed baseline.
**Prototype:** `E:\temp\dell-driver-test\`.

Highest signed-driver yield per request among the OEMs tested. One WinPE pack delivered 57 unique drivers covering network, chipset, storage, GPU and peripheral surfaces — all passing `/kp`.

**Method:** Fetch XML-in-CAB driver catalog → parse embedded XML → download chosen WinPE pack CAB → extract with 7-Zip.

**Pinned artifacts:**
- `https://downloads.dell.com/catalog/DriverPackCatalog.cab` — SHA-256 `1d7c9a5e87fa1be81a00aaef25e6a34a96aaffba2999138659ec69408fa20bab` — 334,958 B.
- `https://downloads.dell.com/FOLDER14542934M/1/WinPE11.0-Drivers-A10-XCXDW.cab` — SHA-256 `38863de5b8ac148c6c32622e643b98e3017fedba33910c48aa2f3cba2956cd21` — 33,410,892 B.

**Notable:** `e1r68x64.sys`, `i40ea68.sys`, `icea68.sys`. **Signature:** 57 / 57 `/kp`.

**Limitations:** Only the WinPE pack family tested. Per-model Driver Packs (end-user EXEs) not exercised; many use InstallShield SFX.

**Integration notes:** Refresh `DriverPackCatalog.cab` with a TTL (~6h; catalog is ~330 KB). Per-model expansion requires InstallShield tooling.

---

## HP

**Role:** OEM, highest-volume source tested.
**Prototype:** `E:\temp\hp-driver-test\`.

Highest raw volume per request of any tested source: 158 drivers from a single SoftPaq. SoftPaq is HP's installer format and uses nested archives.

**Method:** Resolve a SoftPaq URL from HP's WinPE DriverPack HTML page → download the SoftPaq EXE → nested archive extraction (SoftPaq → inner archives → `.sys`).

**Pinned artifacts:**
- `https://ftp.ext.hp.com/pub/softpaq/sp173001-173500/sp173204.exe` — SHA-256 `66bad758aeb46c72ed1a4a4de3244d635169771dd4705b9c230e2b4a42afcd66` — 92,985,536 B.
- `https://ftp.hp.com/pub/caps-softpaq/cmit/HP_WinPE_DriverPack.html` — SHA-256 `3fae1bdfcbab60377b42004e7d0a5e152c1818f227d080b5693a1c7edbc23096` — 11,320 B.

**Notable:** `iaLPSS2_GPIO2.sys`, `iaLPSS2_I2C.sys`, `iaLPSS2_SPI.sys` (Intel LPSS stack). **Signature:** 155 / 158 `/kp`.

**Limitations:** Only WinPE SoftPaq family tested; 3 of 158 failed `/kp` without root-cause investigation.

**Integration notes:** SoftPaq extraction depth can go 3+ levels; enforce depth bound (~5). Prefer `ftp.hp.com` over `ftp.ext.hp.com` where equivalent. The 3 failing drivers are useful `--signature was-valid-ever` fixtures.

---

## Lenovo

**Role:** OEM.
**Prototype:** `E:\temp\lenovo-driver-test\`.

Smaller WinPE pack than Dell/HP but validates a different installer family (Inno Setup, not CAB-direct). Important coverage: Inno Setup appears across the ecosystem.

**Method:** Fetch `catalogv2.xml` → resolve target WinPE EXE URL → extract with `innoextract` (7-Zip alone yields only PE resources, not the payload).

**Pinned artifacts:**
- `https://download.lenovo.com/cdrt/td/catalogv2.xml` — SHA-256 `f581cb806b5a63be6636aad1945e95dabfcb01d6a6c080a1ee0d960a467470f4` — 1,373,849 B.
- `https://download.lenovo.com/pccbbs/mobiles/tp_t14sgen6_amd_mt21m1-21m2_winpe_202410.exe` — SHA-256 `683db1a7ce27fd9047ee2a2f80434784efe0025cf333b6c5e467cee0827665d9` — 1,744,616 B.

**Notable:** `amdgpio2.sys`, `amdi2c.sys`, `amdpmf.sys`. **Signature:** 4 / 4 `/kp`.

**Limitations:** `7z` alone insufficient; needs `innoextract`. Only one model family tested.

**Integration notes:** `innoextract` must be in the pipeline container. Catalog hash matching (XML entry vs downloaded EXE) is a good integrity check — collector should enforce it rather than skipping on mismatch.

---

## Intel

**Role:** Component vendor (NIC family in this test).
**Prototype:** `E:\temp\intel-driver-test\`.

Component vendors distribute drivers directly on their own pages, typically as ZIPs. 68 unique drivers from a single Ethernet driver ZIP.

**Method:** Fetch official Intel Ethernet driver page → download pinned Windows ZIP → 7-Zip.

**Pinned artifact:** `https://downloadmirror.intel.com/923982/Wired_driver_31.2.2_x64.zip` — SHA-256 `2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5` — 40,477,087 B.

**Notable:** `e1c65x64.sys`, `e1d65x64.sys`, `e1r65x64.sys`. **Signature:** 68 / 68 `/kp`.

**Limitations:** `urllib` failed with TLS/HTTP errors; **Windows `curl` with standard TLS validation required**. Only Ethernet family tested.

**Integration notes:** The pipeline container must carry both `python-requests` and `curl` — some sources reject default urllib fingerprints. Decide per-collector which to use. `downloadmirror.intel.com` is the actual payload CDN; discovery pages point to it.

---

## CPU-Z

**Role:** Monitoring utility, BYOVD candidate family.
**Prototype:** `E:\temp\cpuz-driver-test\`.

CPU-Z, HWMonitor and HWiNFO share a driver lineage exposing MSR / port-I/O / physical-memory primitives. BYOVD-grade candidates even when the host application is benign.

**Method:** Download setup EXE and portable ZIP from `download.cpuid.com` → extract application EXEs with `7z -tPE` (plain `7z` destroys PE resource structure) → carve `.sys` from PE resources.

**Pinned artifacts:**
- `https://download.cpuid.com/cpu-z/cpu-z_3.01-en.exe` — SHA-256 `74ab9b1c24fb223d0a5c23e2e444b6cbba7d0c6882cc4bf389e3f88bfca37490`.
- `https://download.cpuid.com/cpu-z/cpu-z_3.01-en.zip` — SHA-256 `8ae3b45d43d97e6ce19535c045cd1e5394c7a3a5334dc01f63edd760ace40827`.

**Notable:** Resource IDs `107`, `108`, `109` (x86/x64/IA64 variants). Driver family maps to `msr-access` scope profile. **Signature:** 2 / 3 `/kp`.

**Limitations:** Resource IDs do not carry original filenames; test preserves the ID as provenance rather than inventing a name.

**Integration notes:** `identity.driver_file` for these should accept a resource ID (`107`) as a legitimate value, not require a `.sys` basename. `--reuse` mode verifies previously downloaded installer hashes before re-fetching; the collector interface should support this.

---

## HWMonitor

**Role:** Monitoring utility, BYOVD candidate (CPU-Z lineage).
**Prototype:** `E:\temp\hwmonitor-driver-test\`.

Shares extraction method and driver lineage with CPU-Z. Separate entry because version cadence and signing state can diverge.

**Method:** Same as CPU-Z — setup EXE + portable ZIP → `7z -tPE` → PE resource carving.

**Pinned artifacts:**
- `https://download.cpuid.com/hwmonitor/hwmonitor_1.68.exe` — SHA-256 `fae15460133a648caca1a63fd809ef0b042cf82daf73c239fa5ac7b062cb2b16`.
- `https://download.cpuid.com/hwmonitor/hwmonitor_1.68.zip` — SHA-256 `8888216170042c9be33771728521df046f6ceecbba397945c976e899570743a6`.

**Notable:** Resource IDs `107`, `108`, `109`. Driver maps to `msr-access` + `arbitrary-physical-memory`. **Signature:** 2 / 3 `/kp`.

**Integration notes:** Collectors for CPU-Z, HWMonitor and HWiNFO can share a base class — the extraction method is identical; only URLs differ.

---

## HWiNFO

**Role:** Monitoring utility, BYOVD candidate.
**Prototype:** `E:\temp\hwinfo-driver-test\`.

Same family as CPU-Z / HWMonitor but ships compressed x64/x86 driver payloads that the current prototype does not decompress. ARM64 driver recovered intact.

**Method:** Setup EXE and portable ZIP from `hwinfo.com` → PE resource carving targeting resource `DRV/725`.

**Pinned artifacts:**
- `https://www.hwinfo.com/files/hwi64_854.exe` — SHA-256 `16281ec83a69a720beac8e2a1dad606fb2eaf4757bb02c7752b72ee2c26ee243`.
- `https://www.hwinfo.com/files/hwi_854.zip` — SHA-256 `6dfd09bf4a0a724bd4b109821fd708b926778a61202c14408311c3db549902fd`.

**Notable:** Resource ID `725` (ARM64 driver). **Signature:** 1 / 1 recovered `/kp`.

**Limitations:** x64 and x86 driver payloads are compressed within the PE resource; decompression not implemented. No application was executed to force runtime extraction.

**Integration notes:** Full coverage requires a decompressor for the embedded x64/x86 payloads. Low priority — ARM64 alone validates the family and the resource-carving pattern.

---

## GIGABYTE

**Role:** OEM utility, BYOVD candidate (amdtools lineage).
**Prototype:** `E:\temp\gigabyte-driver-test\`.

GCC package yielded 9 drivers including `amdtools.sys` / `AmdTools64.sys` — relevant to BYOVD lineages targeting `arbitrary-physical-memory` and `msr-access`. EasyTune5 is referenced across BYOVD catalogs but its installer uses unsupported InstallShield CABs.

**Method:** Fetch official download directory index → try EasyTune5 ZIP (fails on InstallShield CABs) → fall back to full GCC ZIP (436 MiB) → 7-Zip NSIS extraction.

**Pinned artifacts:**
- `https://download1.gigabyte.com/Files/Driver/nb-driver-64bit-win11-dchu-gcc-22.06.23.01.zip` — SHA-256 `698a3a95f51d3178f05a0dae8d5f60873ee47cd61a58823bc3ac6629c83c4d37` — 456,726,360 B.
- `https://download1.gigabyte.com/Files/Driver/desktop_mb21_tool_easytune5.zip` — SHA-256 `c3742dd5386451ea4c8eeac57b5ac08e45f8c733f64ac1aeb98e93088c17d74d` — 4,720,316 B.

**Notable:** `amdtools.sys`, `AmdTools64.sys`. **Signature:** 3 / 9 `/kp`.

**Limitations:** EasyTune5 uses InstallShield CABs the prototype does not handle. Vendor support landing page returns HTTP 403 against automated clients.

**Integration notes:** Container needs both NSIS and InstallShield extractors to cover this source fully; for V1, NSIS alone covers GCC. Use the raw file index (`download1.gigabyte.com/Files/Driver/`) directly, not the support landing page.

---

## MSI Afterburner

**Role:** Tuning utility, confirmed BYOVD (RTCore64 / CVE-2019-16098).
**Prototype:** `E:\temp\msi-afterburner-driver-test\`.

Canonical BYOVD specimen. `RTCore64.sys` is the reference for the entire MSR-access scope and the ground-truth validation case for `clone_hits`. **Expect 0 / 6 passing `/kp`** — correct, and exactly the use case for `--signature was-valid-ever`.

**Method:** Resolve download via the Microsoft `winget` manifest (publishes authorized Guru3D mirror) → download from the Guru3D NLUUG mirror → ZIP + NSIS extraction.

**Pinned artifact:** `https://ftp.nluug.nl/pub/games/PC/guru3d/afterburner/[Guru3D]-MSIAfterburnerSetup466Build16757.zip` — SHA-256 `348e9690a638d84e30e32e9c7c2dd7aad9fd82d71eced1942c04c4c5620b0e1e` — 42,443,037 B.

**Notable:** `RTCore32.sys`, `RTCore64.sys`, `RTCoreMini32.sys`. **Signature:** 0 / 6 `/kp` (expected — revoked).

**Limitations:** MSI's own hosts and Guru3D's landing/direct endpoints return HTTP 403 to scripted clients. Reliant on the authorized Guru3D mirror.

**Integration notes:** **This source only makes sense with `--signature was-valid-ever`.** Use the winget manifest as the authoritative pointer. `RTCore64.sys` is the smoke-test case for L3 clone detection against LOLDrivers.

---

## CORSAIR

**Role:** Peripheral vendor.
**Prototype:** `E:\temp\corsair-driver-test\`.

Peripheral vendors are a documented BYOVD-adjacent surface. Legacy Corsair Link installer uses WiX Burn format — a specific extraction challenge worth cataloging.

**Method:** Download legacy LINK ZIP → carve **both** attached CABs from the WiX Burn EXE → restore payload names from the Burn manifest.

**Pinned artifact:** `https://downloads.corsair.com/Files/Corsair-Link/Corsair-LINK-Installer-v4.9.9.3.zip` — SHA-256 `c288e6a9a97f71ffc287234246452702a4db7ce4829f760466114b8f666d68e7` — 42,371,649 B.

**Notable:** `SiLib.sys`, `SiUSBXp.sys`. **Signature:** 0 / 4 `/kp`.

**Limitations:** Carving only the first Burn cabinet yields bootstrapper files; **both** must be carved. Current iCUE bootstrapper not tested; runtime module retrieval not implemented.

**Integration notes:** Container needs a WiX Burn extractor (`dark.exe` from WiX Toolset, or custom CAB carving). `--signature was-valid-ever` required. iCUE's runtime module retrieval is out of scope for a static pipeline.

---

## Microsoft Surface

**Role:** First-party OEM (Microsoft).
**Prototype:** `E:\temp\surface-driver-test\`.

High-volume MSI source. 36 drivers from one Surface 3 Wi-Fi MSI. Exposes an interesting filename-recovery subproblem.

**Method:** Download MSI from `download.microsoft.com` → 7-Zip extract (yields `fil...` internal identifiers) → read-only `msi.dll` File-table queries restore original filenames **without executing the installer**.

**Pinned artifact:** `https://download.microsoft.com/download/c/5/c/c5c75dc4-0807-44a8-bcc1-6064cfd150f2/Surface3_WiFi_Win10_18362_1902003_0.msi` — SHA-256 `a5eff3977ee26a9bf6c4953333eea58037ddc331039b3d8645cc985d9f27456b` — 191,369,216 B.

**Notable:** `ar0330.sys`, `DptfDevAmbient.sys`, `DptfDevDisplay.sys`. **Signature:** 35 / 36 `/kp`.

**Limitations:** Older model (Surface 3) tested; current Surface line not exercised.

**Integration notes:** Container needs an MSI File-table reader (`msitools` provides `msiinfo` and `msiextract`, both read-only). MSI filename recovery is a reusable utility — applies to VirtIO and any future MSI source.

---

## VirtIO Windows

**Role:** Virtualization / Fedora.
**Prototype:** `E:\temp\virtio-driver-test\`.

Virtualization drivers — different kernel surface than peripheral / consumer utilities. Useful for coverage of non-consumer driver space.

**Method:** Download the official Fedora stable VirtIO MSI → 7-Zip extract + MSI filename restoration (same pattern as Surface).

**Pinned artifact:** `https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-x64.msi` — SHA-256 `4f4388468a7ac5286bd1f1924ef02e7281a60a600390a7cfcfd55809efc0889f` — 4,887,552 B.

**Notable:** `balloon.sys`, `FILE_balloon_2k25_amd64.sys`, `FILE_fwcfg_2k16_amd64.sys`. **Signature:** 26 / 26 `/kp`.

**Limitations:** `urllib` received an HTML anti-bot response with HTTP 200; binary magic validation caught it and Windows `curl` IPv4 was required. Only the smaller MSI tested, not the full VirtIO ISO.

**Integration notes:** Reinforces the `urllib` vs `curl` lesson from Intel — anti-bot defenses target specific HTTP client fingerprints. MSI handling is the same code path as Surface.

---

## WinDivert

**Role:** Non-vendor open-source project.
**Prototype:** `E:\temp\windivert-driver-test\`.

Validates that we can collect from indie / single-project sources, not only OEM pipelines.

**Method:** Download binary ZIP from the official project page → extract directly (no installer).

**Pinned artifact:** `https://reqrypt.org/download/WinDivert-2.2.2-A.zip` — SHA-256 `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15` — 405,137 B.

**Notable:** `WinDivert64.sys`, `WinDivert32.sys`. **Signature:** 0 / 2 `/kp` (real bytes retained with explicit failure logs).

**Limitations:** None material — smallest payload tested.

**Integration notes:** Trivial collector (download + unzip); useful as a baseline implementation reference. Reminder that `/kp` failure does not mean the driver is malicious — just that the local chain does not trust it.

---

## TousLesDrivers

**Role:** Discovery index.
**Prototype:** `E:\temp\touslesdrivers-driver-test\`.

Not a direct source — a hardware-indexed catalog of **vendor-hosted** downloads. Confirms the project's design decision: **TLD for discovery, vendor for download.**

**Method:** Browse TLD's hardware index page → follow the vendor-hosted HTTPS link TLD exposes → download from the vendor host, extract.

**Pinned artifact (NVIDIA-hosted):** `https://us.download.nvidia.com/Windows/nForce/15.26/15.26_nforce_winxp32_international_whql.exe` — SHA-256 `d92f9506889a6a27ab50f5b9ac2e2d5b3fe915ca8bb9019d0fed97b4385a80b1` — 165,744,416 B.

**Notable:** `nvefd2k.sys`, `nvefdxp.sys`, `nvnetbus.sys`. **Signature:** 8 / 8 `/kp`.

**Limitations:** TLD's indexed pages trend toward **historical** releases, not current. Useful for legacy drivers (overrepresented in BYOVD catalogs), not for fresh releases.

**Integration notes:** The collector resolves TLD pages but **never downloads from TLD itself** — downloads always come from the vendor host TLD links to. Treat as orchestration layer / meta-collector that emits per-vendor download URLs for other collectors to ingest.

---

## LOLDrivers

**Role:** Reference catalog of known-vulnerable drivers.
**Prototype:** `E:\temp\loldrivers-reference-test\`.

**Not a collection source.** LOLDrivers is the ingestion source for the `refs/known_vulnerable/` reference set used by L3 clone detection and matched against each scope profile's `clone_cves`.

**Method:** Fetch the official JSON catalog → download one classified non-malicious reference `.sys` → hash-verify against the catalog entry.

**Pinned artifacts:**
- `https://www.loldrivers.io/api/drivers.json` — SHA-256 `bd4a54633d8a8796922c22089f9215e9824d6ef1424370c160ac5c8e7003d50a` — 33,202,785 B.
- `https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/d49368296a3cd000ec0cea88c4bf7edd.bin` — SHA-256 `314a51fcf6e37eb8550a826df085d5c88c43eb1438682f3a6c33632d36956136` — 16,448 B.

**Notable:** `iobios64.sys` — vulnerable-driver reference, hash-matched. **Signature:** 1 / 1 `/kp`.

**Limitations:** JSON catalog grew past the initial 20 MiB limit — bumped to 100 MiB during the test. One sample downloaded as proof-of-mechanism; full ref-set ingestion is a separate build step.

**Integration notes:** **Different pipeline role.** LOLDrivers feeds the reference set used by **every** analysis run; it is not a per-driver collection source. `clone_ref` flag format: `loldrivers@<catalog-date>`. Catalog should be re-fetched periodically; the catalog's own SHA-256 serves as the version tag. GitHub LFS payloads have `.bin` extension and must be validated as PE on ingest.

**Not explored in the first pass:** LOLDrivers also publishes a `detections/` subtree (`https://github.com/magicsword-io/LOLDrivers/tree/main/detections`) with eight formats of pre-made defender rules — `yara/`, `sigma/`, `sigma-per-driver/`, `sysmon/`, `wdac/` (WDAC blocklist XML), `hashes/`, `av/`, `lacework/`. The initial research only pulled `api/drivers.json`. The ingestion step planned in Pending #5 should mirror `detections/yara/` (usable as an L1 pre-scanner, stronger signal than TLSH fuzzy-hash) and `detections/sigma-per-driver/` (ground-truth reference for the AI's `detection_ideas` output), at minimum. See the README's Pending #5 note.

---

## Additional sources — second pass

Eighteen more sources confirmed in a follow-up run under `E:\temp\additional-driver-sources\`, adding **64 unique drivers**. All 64 hashes are distinct within the second-pass set; cross-pass dedup against the first 16 sources has not been computed. Detail is lighter than the first pass: method and package tested are recorded, but per-artifact SHA-256 inventory is in `verified-sources.json` rather than this catalog.

### Dokany

**Role:** Userland FS driver project (filter-class territory, FUSE-like).
**Discovery:** `https://github.com/dokan-dev/dokany/releases`
**Package tested:** `Dokan_x64.msi`.
**Count:** 1 driver, 1 / 1 `/kp`.
**Notes:** Collector shares the `discover_more.py` family under `E:\temp\driver-source-tools\`; row in `verified-sources.json`.

### Focusrite

**Role:** Audio peripheral vendor — new category coverage.
**Discovery:** `https://downloads.focusrite.com/focusrite/scarlett-2nd-gen/scarlett-2i2-2nd-gen`
**Package tested:** `Focusrite_Usb_4.65.5.658.exe`.
**Count:** 4 drivers, 0 / 4 `/kp` (expected for older signed releases — `--signature was-valid-ever` territory).
**Notes:** Validates that audio-vendor configurators are collectible with the generic installer-extraction path.

### ImDisk / LTR Data

**Role:** Virtual disk / image mount driver (`disk`-class, filter-class territory).
**Discovery:** `https://www.ltr-data.se/opencode.html/#ImDisk`
**Package tested:** `imdiskinst.exe`.
**Count:** 5 drivers, 5 / 5 `/kp`.
**Notes:** Clean signed baseline for a mount-filter family historically referenced in BYOVD research. Relevant to the `disk-raw-io` scope profile.

### libusb-win32

**Role:** USB generic driver (open-source, long-lived).
**Discovery:** `https://github.com/mcuee/libusb-win32/releases`
**Package tested:** `libusb-win32-bin-1.4.0.2.zip`.
**Count:** 3 drivers, 0 / 3 `/kp` (older signatures — `--signature was-valid-ever` territory).
**Notes:** ZIP distribution, trivial extraction. Companion to UsbDk/USBPcap in the USB-class corpus.

### Npcap

**Role:** Network capture driver (WinPcap successor).
**Discovery:** `https://npcap.com/`
**Package tested:** `npcap-1.89.exe`.
**Count:** 1 driver, 1 / 1 `/kp`.
**Notes:** Important `net`-class reference — Npcap is widely bundled by other tools (Wireshark, Nmap). Likely to appear cross-sourced elsewhere.

### OpenVPN

**Role:** VPN tunnel driver (TAP adapter).
**Discovery:** `https://openvpn.net/community/`
**Package tested:** `openvpn-latest-stable-amd64.msi`.
**Count:** 2 drivers, 2 / 2 `/kp`.
**Notes:** MSI handling path (same as Surface / VirtIO). Clean signed baseline for the `net`-class scope.

### PassMark OSFMount (legacy)

**Role:** Virtual disk / image mount driver — companion to ImDisk.
**Discovery:** `https://www.osforensics.com/tools/mount-disk-images.html`
**Package tested:** `osfmount_x64_v2.0.1001.exe` (legacy build).
**Count:** 2 drivers, 0 / 2 `/kp`.
**Notes:** The *current* OSFMount installer was in the "attempted but failed" bucket (no native PE driver extracted); the legacy build succeeded. Signature failures are expected for the legacy release — `--signature was-valid-ever` territory.

### Prolific

**Role:** USB-serial component vendor (PL2303 family).
**Discovery:** `https://www.prolific.com.tw/portfolio-item/pl2303ge/`
**Package tested:** `PL2303G_DCHU_DFx.zip`.
**Count:** 3 drivers, 3 / 3 `/kp`.
**Notes:** Clean signed baseline for the USB-serial controller class. Corresponds to TLD category 21 (Carte contrôleur).

### Samsung NVMe

**Role:** Component vendor (storage, `disk`-class).
**Discovery:** `https://semiconductor.samsung.com/resources/software-resources/`
**Package tested:** `Samsung_NVM_Express_Driver_3.3.exe`.
**Count:** 8 drivers, 6 / 8 `/kp`.
**Notes:** Relevant to the `disk-raw-io` scope profile. 2 failing `/kp` are candidates for `--signature was-valid-ever` fixtures.

### Microsoft Sysinternals

**Role:** First-party admin tooling (Microsoft).
**Discovery:** `https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer`
**Package tested:** `ProcessExplorer.zip`.
**Count:** 3 drivers, 3 / 3 `/kp`.
**Notes:** Clean WHQL baseline from a widely trusted first-party source. PE-resource carving from the application EXE (same pattern as CPU-Z / HWMonitor). Useful golden reference for signed-driver sanity checks.

### UsbDk

**Role:** USB filter driver (`usb`-class).
**Discovery:** `https://github.com/daynix/UsbDk/releases`
**Package tested:** `UsbDk_1.0.22_x64.msi`.
**Count:** 5 drivers, 0 / 5 `/kp`.
**Notes:** Companion to VirtIO/VirtualBox ecosystems. All five failing `/kp` is unusual — worth verifying whether the signatures are revoked or merely untrusted on the test machine.

### USBPcap

**Role:** USB capture driver (`usb`-class — Wireshark USB companion).
**Discovery:** `https://github.com/desowin/usbpcap/releases`
**Package tested:** `USBPcapSetup-1.5.4.0.exe`.
**Count:** 1 driver, 0 / 1 `/kp` (`--signature was-valid-ever` territory).
**Notes:** NSIS installer extraction. USB-class companion to UsbDk and libusb-win32.

### VeraCrypt

**Role:** Full-disk encryption driver (`disk`-class filter).
**Discovery:** `https://veracrypt.io/en/Downloads.html`
**Package tested:** `VeraCrypt_Setup_x64_1.26.29.msi`.
**Count:** 1 driver, 1 / 1 `/kp`.
**Notes:** MSI handling path. Relevant to the `disk-raw-io` and filter-class scopes.

### Oracle VirtualBox

**Role:** Virtualization — second virtualization source after VirtIO.
**Discovery:** `https://www.virtualbox.org/wiki/Downloads`
**Package tested:** `VirtualBox-7.2.20-175154-Win.exe`.
**Count:** 12 drivers, 10 / 12 `/kp`.
**Notes:** Highest-volume second-pass source. VirtualBox has published kernel CVEs historically; worth running against the `arbitrary-physical-memory` and `process-token-manipulation` profiles once the pipeline exists.

### vJoy

**Role:** Virtual HID / joystick driver (`hid`-class).
**Discovery:** `https://github.com/njz3/vJoy/releases`
**Package tested:** `vJoySetup-2.2.1-signed.exe`.
**Count:** 2 drivers, 0 / 2 `/kp` (`--signature was-valid-ever` territory).
**Notes:** Relevant to the `hid-input-control` scope profile — a virtual HID stack is useful coverage alongside real peripheral vendors.

### WinBtrfs

**Role:** Filesystem driver (open-source Btrfs on Windows).
**Discovery:** `https://github.com/maharmstone/btrfs/releases`
**Package tested:** `btrfs-1.10.zip`.
**Count:** 4 drivers, 0 / 4 `/kp` (`--signature was-valid-ever` territory).
**Notes:** True in-kernel filesystem (not userland-FS), unlike Dokany/WinFsp. ZIP distribution.

### WinFsp

**Role:** Userland FS driver project (filter-class).
**Discovery:** `https://github.com/winfsp/winfsp/releases`
**Package tested:** `winfsp-2.1.25156.msi`.
**Count:** 3 drivers, 3 / 3 `/kp`.
**Notes:** Companion to Dokany — same category, similar extraction path. Clean baseline for the `filter`-class.

### Wintun

**Role:** Modern tunnel driver (WireGuard-era TUN).
**Discovery:** `https://www.wintun.net/`
**Package tested:** `wintun-0.14.1.zip`.
**Count:** 4 drivers, 3 / 4 `/kp`.
**Notes:** ZIP distribution + PE resource extraction. Note: WireGuard itself was in the "attempted but failed" list below — Wintun is the related, successfully-extracted sibling.

## Attempted but not yet successful

Documented so a future pass does not re-try these without a plan:

| Source | Reason |
|---|---|
| AMD | No valid native PE driver extracted (extraction method did not find a `.sys` in the tested package) |
| ASRock | No valid native PE driver extracted |
| FTDI | HTTP 403 on both `urllib` and `curl` — vendor hosts block scripted downloads |
| HidHide | No valid native PE driver extracted |
| PassMark OSFMount (current) | No valid native PE driver extracted (the *legacy* build succeeded — see second-pass entry) |
| Silicon Labs | HTTP 403 on both `urllib` and `curl` |
| SoftPerfect | No valid native PE driver extracted |
| ViGEmBus | No valid native PE driver extracted |
| WireGuard | No valid native PE driver extracted (Wintun, the related driver, worked) |
| Yamaha / Steinberg | No valid native PE driver extracted |

**"No valid native PE driver extracted"** typically means the installer contains kernel drivers but the extraction method applied did not recover them. The next pass needs installer-specific tooling, not a generic retry — these are deferred to a per-source dive rather than another generic sweep.

---

## What this round of research unlocks

- **Pending #1 (collection sources research) is substantially resolved.** Sixteen sources with documented methods, three BYOVD-relevant specimens already in hand (`RTCore64.sys`, `amdtools.sys`, `iobios64.sys`), and operational know-how (urllib → curl fallback, authorized mirrors for revoked-signature families, MSI File-table filename recovery, PE-resource carving for utility drivers).
- **L3 clone detection can be smoke-tested immediately** using the LOLDrivers reference sample and the MSI Afterburner payload once the clone pipeline exists.
- **`--signature was-valid-ever` has concrete validation cases** — any source where the pass count is less than the recovered count exercises this flag.

## What is not covered yet

- Dell / HP / Lenovo per-model Driver Packs (end-user EXEs, often InstallShield SFX).
- CORSAIR iCUE runtime module retrieval (requires executing the bootstrapper, out of scope).
- HWiNFO compressed x64/x86 payloads (compressor not implemented in prototype).
- Automated catalog refresh cadence per source (TTL policies still to be decided).
- The actual pipeline ingestion step that maps `E:\temp\*\sys\<sha256>.sys` into `reports/<sha256>/`.
