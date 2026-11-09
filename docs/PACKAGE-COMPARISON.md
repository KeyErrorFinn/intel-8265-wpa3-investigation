# Intel vs Dell driver package comparison

A static comparison of the Windows driver packages that could be installed on an Intel Dual Band Wireless-AC 8265 (PCI `VEN_8086&DEV_24FD`), done to answer one question: **does any packaged Windows driver for this card implement WPA3-SAE, and would a different or newer package fix the problem?**

This is static analysis of signed vendor packages. Nothing was installed or executed, no radio was used and nothing here was tested on the 8265. No vendor binaries or raw disassembly are published; only file names, versions, sizes, hashes and conclusions.

## Packages examined

| Package | Signer | Notes |
|---|---|---|
| `WiFi-22.200.2-Driver64-Win10-Win11.exe` (Intel, SHA-256 `FE5BF9207C8D57E59B6BB48059824F97AB583F878F06A9B175A55A54A3E353AC`) | Intel Corporation | Generic Intel package. 41,329,152 bytes. |
| `Intel-9560-9260-8265-7265-3165-Wi-Fi-Driver_FCCJ9_WIN_22.130.0.5_A30_05.EXE` (Dell, SHA-256 `C4140B91D6F0EF856219C3F7D1B1C3CE99A9822E1C6969AA981F943BDBC8190E`) | Dell Inc | Dell OEM package. 86,178,472 bytes. Hash matches the one published by the third-party mirror it was first found on. |

Both were unpacked with 7-Zip. The Intel installer is a PE wrapper around a custom container that holds an MSI-style CAB; the driver files inside carry opaque key names (`a21`, `a26`, …) and were identified by content (PE version info and the INF they belong to).

## Which driver the 8265 gets

In both packages the 8265 is listed only in the `Netwtw06` INF. No `Netwtw08`, `Netwtw10`, `Netwtw12` or `Netwaw10` INF contains `DEV_24FD`.

| Package | 8265 driver | Version | Size | SHA-256 |
|---|---|---|---|---|
| Intel 22.200.2 | `Netwtw06.sys` | 20.70.32.1 | 8,902,232 | `615DBE4C4393B3B7B547BE1E602FC9D30D2EEBDA4B0CA5ED730C2217FF672BA1` |
| Dell 22.130.0.5 | `NETwtw06.sys` | **20.70.30.1** | 8,899,176 | `41A7819D6BA1FE9A92612A85E112DF6F565B2D61B529A0E15F85F880174C9470` |

The "22.130.0.5" in Dell's file name is the version of the newer-chip drivers in the same bundle, not of the 8265's driver. Dell's 8265 driver is older than Intel's final one. Installing Dell's package therefore cannot add anything the Intel package lacks, for this card.

Other drivers in the packages, for reference:

| Driver | Version(s) | Chips (from INF) | WPA3 name strings |
|---|---|---|---|
| `Netwtw04` | 19.51.40.1 (Dell), 19.51.42.2 (Intel) | 3165, 3168, 7265 | none |
| `Netwtw06` | 20.70.30.1 (Dell), 20.70.32.1 (Intel) | **8260, 8265**, 8275, 4165 | none |
| `Netwtw08` | 21.80.22.1 (Dell), 21.80.27.1 (Intel) | installed via the `Netwtw10` service in Dell's INF | `SAE FT` only |
| `Netwtw10` / `Netwtw12` | 22.130.0.5 (Dell), 22.180.10.1 and 22.200.2.1 (Intel) | 9260, 9461/9462, 9560, AX200/AX201, AX210/AX211/AX411 | `WPA3 SAE`, `WPA3 OWE`, `WPA3 ENT`, `SAE FT` |
| `Netwaw10` | 22.130.0.5 (Dell) | not examined in detail | `WPA3 SAE`, `WPA3 OWE`, `SAE FT` |

## Static comparison of Netwtw06 and Netwtw12

Both drivers are NDIS miniports from the same Intel build pipeline (PDB paths `...Netwtw06.pdb` and `...Netwtw12.pdb`; built 2022-07 and 2023-03).

1. **Authentication-algorithm naming/handling.** In `Netwtw06` the function that handles the enabled-authentication-algorithm OID builds a name table of eight entries (`INVALID` plus `DOT11_AUTH_ALGO_` `80211_OPEN`, `80211_SHARED_KEY`, `WPA`, `WPA_PSK`, `WPA_NONE`, `RSNA`, `RSNA_PSK`), i.e. algorithm values 0 to 7. Dell's `Netwtw06` 20.70.30.1 has the same 533-byte function with the same seven names. In `Netwtw12` the corresponding function switches over values 1 to 11 and names `WPA3 ENT 192`, `WPA3 SAE`, `WPA3 OWE` and `WPA3 ENT`, plus the `GCMP-128`, `GCMP-256` and `GMAC-256` ciphers.
2. **RSN extension and H2E.** `Netwtw06` contains no `RSNXE` or `H2E` strings. `Netwtw12` 22.200.2.1 contains both. Management-frame-protection (`MFP`) and SA Query strings exist in both, so basic 802.11w handling is not new in the newer driver.
3. **Where SAE appears.** In `Netwtw12` 22.200.2.1, five separate functions reference SAE-related names: two reference the `WPA3 SAE`/`WPA3 OWE`/`WPA3 ENT` names (the algorithm-naming function above and one more) and three reference `SAE FT`. In `Netwtw06` no whole-word `SAE`, `WPA3`, `H2E` or `OWE` string exists (a plain substring count is misleading: `OWE` matches inside words such as `POWER`). The earlier emulation work in [FINDINGS](FINDINGS.md) found the SAE property handler slot unregistered.

What these results support: neither packaged 8265 driver implements WPA3-SAE, and the WPA3 support Intel added later was never backported to the 8260/8265 branch. This agrees with the existing [findings](FINDINGS.md) on that branch.

## What this does not show

- Items 1 and 2 are from naming/logging tables and string presence, not a trace of full capability negotiation. A driver could in principle handle a mode without these strings; that would be unusual but is not excluded.
- Nothing here shows the 8265 **hardware or firmware** cannot do WPA3, and the project's earlier correction that hardware impossibility was overclaimed still applies. The firmware blobs (`Netwfw06.dat` and the others) were not analysed.
- An attempt to find a plain table of supported algorithm values in either driver (runs of consecutive dwords, runs of constant stores) found nothing, so the location where each driver reports its supported algorithms to Windows is **not identified**.
- Nothing here was run on the 8265 or any radio.

## Practical consequences

- Neither Intel's final generic package nor Dell's OEM package can give the 8265 WPA3 on Windows. The driver branch for this card stops at 20.70.x.
- The same Dell bundle does contain WPA3-capable drivers for the 9260/9560/AX200/AX210 families. Replacing the card with one of those is the route that needs no driver development. This was not tested, and the laptop's BIOS may restrict which M.2 cards it accepts.
- WPA2/WPA3 transition mode on the access point avoids the problem without changing the driver.

## Reproducing the checks

The scripts are in `tools/package_analysis/` and need Python 3.11+ with the third-party packages `capstone` and `pefile`. They are separate from the portable test suite and are not run by it.

```console
python -m venv .venv
.venv\Scripts\pip install capstone pefile
.venv\Scripts\python tools\package_analysis\summary.py path\to\Netwtw06.sys path\to\Netwtw12.sys
.venv\Scripts\python tools\package_analysis\check_auth.py path\to\Netwtw06.sys path\to\Netwtw12.sys
```

- `summary.py`: PE header, section, PDB path and import summary.
- `check_auth.py`: lists WPA3 and legacy `DOT11_AUTH_ALGO_*` strings and the functions that reference them.
- `disasm_va.py <driver> <start-va> <end-va>`: disassembles a range with string annotations (prints disassembly to the terminal; do not commit its output).
- `xref.py`: shared helper module (string finding, RIP-relative cross-references, function bounds via `.pdata`).

Extract the vendor packages yourself into an empty folder, never run the installers, and run any Python that reads untrusted files with `-I`.
