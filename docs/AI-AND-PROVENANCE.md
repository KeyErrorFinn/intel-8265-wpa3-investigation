# AI assistance and provenance

The repository owner initiated the problem, supplied the laptop context and directed the investigation. Codex and delegated AI agents generated most of the analysis scripts, experimental C/Python code, tests and draft documentation. This public curation and its verification were also AI-assisted. No independent human authorship, expert review or production readiness is claimed.

## Included material

- `sae_wdi_codec.py`: AI-generated reference implementation of documented WDI TLV formats.
- `native/sae_codec.c/.h`: AI-generated bounded parsing and encoding components. Protocol definitions were compared with Microsoft's WDI schema and public hostap behaviour during the investigation.
- `native/sae_session.c/.h`: a new caller-serialized API. It is not Intel's recovered connection implementation.
- `native/sae_intel_binding.h`: a narrow, build-specific identity-view API. It neither owns Intel objects nor proves their lifetime.
- Tests: AI-generated synthetic inputs and regression checks. They do not establish cryptographic correctness or kernel safety.
- Fixture JSON: sanitized outputs from controlled offline experiments, containing synthetic inputs/object views rather than proprietary executable instructions or live captures.

The fixture provenance reflects the earlier experiment records. Re-running this public suite consumes the saved fixtures; it does not independently re-execute Windows/Intel code. Shared assumptions between the Python and C implementations can survive differential testing.

## Package comparison (Claude)

`docs/PACKAGE-COMPARISON.md` and `tools/package_analysis/*.py` were produced in a separate session by Anthropic's Claude (Claude Code, Sonnet 5.5) working under the repository owner's direction. The session downloaded the two vendor packages, unpacked them without executing them, ran the scripts, and wrote the document. The scripts are AI-generated, were exercised only against the examined 8265 driver builds, and have not been independently reviewed. Their conclusions rest on string and cross-reference analysis, not on live hardware.

## Excluded material

No Intel or Windows executable, PDB, WDK header/XML, downloaded upstream source, raw proprietary disassembly, toolchain, live memory dump, packet capture, private network identifier or full chat transcript is included. The raw working archive is not a release asset.

## Primary references

- [Microsoft: WPA3-SAE driver authentication](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wpa3-sae-authentication)
- [Microsoft: WDI SAE property request](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-wdi-set-sae-auth-params)
- [Microsoft: WDI SAE indication](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ndis-status-wdi-indication-sae-auth-params-needed)
- [Intel: final 8260/8265 Windows driver](https://www.intel.com/content/www/us/en/download/777192/intel-wireless-wi-fi-drivers-for-intel-dual-band-wireless-ac-8260-and-intel-dual-band-wireless-ac-8265.html)
- [Linux v6.6 mac80211 authentication/association](https://github.com/torvalds/linux/blob/v6.6/net/mac80211/mlme.c)
- [Linux v6.6 iwlmvm TX](https://github.com/torvalds/linux/blob/v6.6/drivers/net/wireless/intel/iwlwifi/mvm/tx.c)
- [Linux v6.6 iwlmvm key handling](https://github.com/torvalds/linux/blob/v6.6/drivers/net/wireless/intel/iwlwifi/mvm/sta.c)
- [Pinned Android hostap SME](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/tags/android-14.0.0_r1/wpa_supplicant/sme.c)
- [Zig official releases](https://ziglang.org/download/)

No blanket license is assigned to referenced third-party material. The initial publication has no LICENSE file; a license decision can follow a separate provenance review.
