# Intel 8265 WPA3 investigation

An AI-assisted investigation into a real Wi-Fi interoperability problem: an Intel Wireless-AC 8265 laptop could connect to a WPA3-Personal network under Linux, but Windows returned **“Can't connect to this network.”**

**Status: incomplete research. This repository does not contain a working Windows Wi-Fi driver, installable patch, or proven WPA3 connection fix.** The included native libraries are user-mode validation components. Do not install them as drivers.

## Why this project exists

I wanted to understand why the same laptop worked on Linux and failed on Windows, and whether a software solution was possible. The investigation expanded from Windows diagnostics into driver-interface research and experimental C components. It did not achieve the original connection goal.

I am publishing a curated record of the attempt: the useful findings, testable components, mistakes, and the point where the evidence stopped supporting further claims.

## AI contribution

OpenAI Codex and its subagents performed substantial source review, binary analysis, code generation, testing and documentation under my direction. This is **not a claim that I independently wrote or reverse-engineered all of the code**. The public code remains experimental and has not received independent kernel-driver or security review. See [AI assistance and provenance](docs/AI-AND-PROVENANCE.md).

## Main findings

- Windows advertised no WPA3 support for the 8265 after updating to Intel's final driver, 20.70.32.1.
- Linux's SAE support spans userspace authentication, the shared wireless state machine and ordinary driver frame/key transport. It is not a single hardware switch.
- Controlled emulation of the examined Windows driver found missing SAE command registration and legacy authentication continuations incompatible with a complete SAE exchange.
- Native payload codecs, receive/transmit-body adapters, association-IE encoding and a caller-serialized session gate were implemented and tested offline.
- Those components were never integrated into a safely loadable kernel driver. Connection lifetime, cancellation, complete transport/association/key integration and physical validation remain unfinished.

The failure log alone did not prove the diagnosis. Earlier hardware-impossibility claims were too strong, and growing test counts did not mean an installable driver was close. [Findings and corrections](docs/FINDINGS.md) explains these limits.

## What's included

| Area | Contents | Limits |
|---|---|---|
| Python reference | Owned SAE WDI payload parser/encoder | No cryptography or network access |
| Native C | Codec, body adapters, session gate and pinned-layout identity reader | No kernel entry, hooks, synchronization or hardware transport |
| Tests | Synthetic vectors, malformed input, ownership checks, mutation comparisons and session ordering | No physical radio or valid cryptographic exchange |
| Research notes | Architecture comparison, evidence levels, corrections and unresolved work | Selected conclusions; raw proprietary disassembly is not published |

The fixture object addresses and MAC addresses are synthetic. They are not a live memory dump or radio capture.

## Run the portable tests

Python 3.10 or later, standard library only:

```console
python run_tests.py
```

## Build and test the native components

Windows x64, Python 3.10+ and Zig 0.17.0:

```console
python native/build.py --zig PATH_TO_ZIG_EXE
python run_tests.py --native
```

An optional `python tools/fetch_zig.py` downloads the approximately 100 MB Windows toolchain from Zig's official release index and verifies its published SHA-256 into the ignored `.tools` folder. It does not install software or change PATH. Use the printed executable path with `--zig`.

The build emits a no-CRT user-mode DLL and freestanding objects. Build output stays local and is ignored by Git. The test workflow reproduces these commands; a workflow definition is not a claim that GitHub-hosted CI has already passed.

These native tests load DLLs into a normal user-mode Python process. They do not load kernel code. Treat any modified native code as ordinary executable code requiring review.

## Evidence and reproduction

The public suite runs independently of Intel/Windows binaries, WDK downloads and the original workstation. Saved synthetic vectors are described in [testing scope](docs/TESTING.md). Earlier original-code emulation experiments are documented as historical observations; this repository does not reproduce those experiments or redistribute their executable inputs.

This repository deliberately excludes credentials, workplace network identifiers, live diagnostics, personal local paths, vendor binaries, WDK files, copied upstream implementations, toolchains and compiled artifacts.

## Current outcome

The original Windows connection problem remains unresolved. A hardware-tested, safely cancellable SAE exchange was **not** achieved. Further driver development would require an integrated kernel implementation, established lifecycle contracts, a legitimate signing/loading route and a recoverable hardware test setup.

This is a research record, not an Intel, Microsoft, Dell or network-vendor project. No affiliation or endorsement is implied. No software license has been selected for this initial publication; third-party references retain their own terms.
