# Findings, corrections and stopping point

## Starting problem

A Dell Latitude 7490 with an Intel Wireless-AC 8265 could use a particular network on Linux while Windows rejected the connection. Windows could connect to a separate WPA2 hotspot. A Windows scan advertised WPA3-Personal for the target network, while the installed adapter capabilities omitted WPA3. Updating to the final Intel 20.70.32.1 branch did not resolve it.

The working Linux connection's negotiated security and exact software versions were not independently recorded. The scan is not a complete audit of every access point's AKM configuration. Network authorization after successful authentication was outside the achieved work.

## Architecture comparison

Hostap prepares/verifies SAE data. Linux mac80211 accepts variable authentication data, tracks transactions and retry responses, and keeps authentication separate from association. Intel's Linux hardware layer transports frames and installs derived cipher keys. Windows supplies SAE cryptographic processing but requires its driver to implement the WDI exchange and correct connection handling.

Linux therefore provides useful behavioural guidance. It does not provide Intel's private Windows object, lock, callback or firmware contracts. We did not establish that Linux and Windows use interchangeable firmware. A complete Linux-to-Windows hardware-driver port would be a substantially larger project.

## Selected historical binary observations

Controlled offline experiments against a pinned Intel driver build reported:

1. The authentication-mode conversion rejects WPA3-SAE, and the constructed command table has no SAE property handler in slot 135.
2. Original frame serialization accepts variable-length synthetic authentication bodies. An early inference that a 16-byte internal buffer meant a global on-air size limit was wrong.
3. Received authentication bodies are retained even if legacy IE parsing fails. A native receive adapter can encode those bodies for Windows' documented format.
4. The legacy connection continuation can reject SAE retry status or advance toward association after a commit before OS verification finishes.
5. A task pointer may remain in its port slot while destruction/free occurs. Identity bytes are not a safe object reference.

These are historical observations from emulation with explicit environment substitutions, not published live-hardware results. Vendor executables and raw disassembly are excluded. The public tests do not rerun those experiments.

A later static comparison of the Intel and Dell driver packages, and of the `Netwtw06` and WPA3-capable `Netwtw12` drivers, is in [PACKAGE-COMPARISON.md](PACKAGE-COMPARISON.md). It supports the conclusion that no packaged driver for this card implements WPA3-SAE, with its own stated limits.

## Implemented components

The native code parses owned WDI request data, encodes indications and authentication bodies, writes a narrow association security configuration and exposes a new session gate. The gate models generation/peer checks, OS success, outstanding TX leases, cancellation and explicit quiescence. Its caller must provide real serialization, storage lifetime and transport semantics. It is not an installed driver state machine.

The pinned-layout identity reader accepts bounded supplied object views. It does not follow or validate arbitrary live kernel pointers, acquire references, install hooks or establish a safe execution domain.

## Corrections that mattered

- WPA3 absence in this Windows driver is not proof of a physical radio limitation.
- SAE-related strings can be diagnostic helpers rather than implemented handlers.
- Enqueueing a management event is not proof of radio transmission.
- A generic “authentication parameters” helper was actually fast-transition handling.
- The early routing-table inference confused port routing with command dispatch.
- Completed OID status does not necessarily mean an asynchronous connection task has ended.
- Passing more isolated tests does not establish integration or an approaching release.

## Why the attempt stopped

No integrated kernel module binds the new components to capabilities, command registration, live connection ownership, AUTH/FLUSH gating, transport, indications and key handling. Completion, timeout and port-teardown domains are not sufficiently established to guarantee safe lifetime. No physical SAE exchange, successful association, installed key or usable network traffic was demonstrated.

The project remains incomplete. The next meaningful success criterion would be an integrated, properly signed test candidate that performs one real exchange and safely cancels/tears down. Elevation or a permissive filesystem alone does not provide that implementation.
