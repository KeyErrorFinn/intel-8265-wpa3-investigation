# Testing scope

## Local publication check — 3 November 2026

The curated repository was rebuilt with Zig 0.17.0 on Windows x64. `python run_tests.py --native` completed successfully: **10 standalone Python tests + 47 native tests = 57 tests**. The native codec suite includes 1,500 deterministic mutation comparisons. The generated no-CRT DLL was used only for user-mode validation and is not committed.

This count is deliberately smaller than the private research workspace's historical count: tests requiring proprietary executables, WDK files or an upstream parser DLL were excluded. GitHub-hosted CI had not run when this local result was recorded.

## Public suite

`python run_tests.py` runs the standalone reference codec tests using standard Python. The WDK XML/header verification from the private workspace is intentionally excluded; the public tests require no WDK assets.

After building on Windows x64, `--native` runs:

- `test_native.py`: codec ownership, bounds, malformed input, version handling, synthetic fixture vectors, receive adapters and 1,500 deterministic mutations compared with the Python reference.
- `test_session.py`: the new session API under controlled ordering, cancellation and quiescence conditions. It is not a kernel concurrency test.
- `test_intel_binding.py`: a build-specific identity reader against saved synthetic object views, including the important case where destructor-entry bytes still look valid. Acceptance is not a lifetime guarantee.
- `test_tx_body.py`: synthetic SAE commit/confirm body encoding, capacity and overlap guards. Original-binary serializer tests have been removed from the public suite.

The original upstream hostap parser-based association test is also excluded, since its copied source and oracle DLL are not published here. Association encoding remains experimental, and this public suite should not be described as reproducing all historical validation.

## Fixture provenance

`windows-sae-vectors.json` contains five synthetic request vectors recorded in earlier original-Windows-code emulation. Cryptographic fields are placeholder bytes. No network credentials or radio capture is present. The historical flag describes that earlier experiment, not what a public test executes today.

`connect-object-views.json` contains selected synthetic port/task views from a controlled emulation fixture. Addresses belong to an emulated address space. These are inert test bytes, not executable driver instructions or a live memory dump. The source binary hash identifies the studied build without distributing it.

## Limits

No test loads a kernel driver, transmits a frame, validates SAE cryptography, proves firmware acceptance, installs a hardware key or establishes a real connection. Native tests execute generated DLL code in a normal Python process. Differential tests can agree on a shared mistake. Passing tests are evidence about the tested components and conditions only.
