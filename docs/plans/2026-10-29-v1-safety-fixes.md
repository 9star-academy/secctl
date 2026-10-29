# V1 Safety Fixes Implementation Plan

**Goal:** Fix the verified SSH, firewall, Docker Shield and documentation defects without adding Go dependencies.

**Architecture:** Keep the existing CLI and packages. Replace successful mock fallbacks with explicit unavailable errors. Require successful command execution and live-state verification. Schedule SSH rollback with systemd before writing config so it survives the invoking process. Support Docker Shield through active UFW and Docker's iptables chains; reject unsupported environments.

**Tech Stack:** Go standard library; existing Linux tools (OpenSSH, systemd, UFW, iptables).

## Tasks

1. Add regressions for backend absence, real deny rules, input validation, command failures and configuration semantics. Run failing tests first.
   Files: `internal/firewall/*_test.go`, `internal/ssh/*_test.go`, `internal/dockershield/*_test.go`, `internal/cli/cli_test.go`.
2. Fix firewall fallback, protocol/range/source handling and deny precedence; explicitly distinguish host and routed Docker rules. Verify generated commands with stub runners.
   Files: `internal/firewall/firewall.go`, `iptables.go`, `ufw.go`, `internal/cli/cli.go`.
3. Add durable systemd rollback state and hidden recovery command; validate effective SSH configuration before changes, propagate reload/firewall failures, reject unsupported Match scopes safely.
   Files: `internal/ssh/config.go`, `manager.go`, `rollback.go`, `internal/cli/cli.go`.
4. Replace Docker no-op rules with a private filtering chain, UFW forwarding ACL integration and explicit lifecycle; persist through UFW rules, check actual kernel rules and rollback failed configuration.
   Files: `internal/dockershield/shield.go`, `shield_test.go`.
5. Correct audit claims/unknown status, installation path and unimplemented feature promises. Add CI on pushes/PRs, race/vet/build checks and installer syntax check.
   Files: `internal/audit/*`, `README.md`, `scripts/install.sh`, `.github/workflows/*`.
6. Run `go test -race -coverprofile=... ./...`, `go vet ./...`, four cross-builds, installer syntax and `git diff --check`. Add an opt-in isolated Linux integration script for actual packet-path/restart acceptance; never change this Mac's SSH or firewall.

## Acceptance

- Missing tools and command failures cannot report protection or success.
- Deny produces a higher-priority blocking rule; unsupported options fail before mutation.
- Include ordering cannot silently defeat password hardening. Unsupported Match configurations fail before writing.
- SSH config is backed up and independent rollback is scheduled before apply; confirmation cancels it; rollback errors propagate.
- Docker protection has an active forwarding hook, filters new inbound container connections, preserves established/egress traffic and can be removed without touching unrelated rules.
- Document unverified Linux runtime/reboot behavior and remaining support limits honestly.

## Progress

- [x] Review and design approved through the user's fix request.
- [x] Regression tests and firewall fixes.
- [x] SSH transaction and rollback.
- [x] Docker Shield lifecycle.
- [x] Audit, docs, CI and final local verification.

## Verification notes

- Existing and new Go tests pass so far, including command failure propagation, Include ordering, conditional-config rejection, independent rollback state and Docker lifecycle with isolated command stubs.
- Local host has no Linux VM/container runtime; real packet-path, service-restart and reboot acceptance remains a separately documented integration check.
- Native iptables remains explicitly IPv4/runtime-only. Docker Shield is narrowed to active UFW + Docker iptables IPv4 bridge, rejecting IPv6 containers and unsupported backends.
- Replaced old fake public-key fixtures with correctly encoded wire-format fixtures.

- Added checksum installer tests with stubbed downloads/install destinations; no system writes. Added confinement of authorized_keys writes using Go 1.24 os.Root and file descriptors to preserve ownership without path escape.

- Final review checked UFW implementation: duplicate insertions can be skipped even when the existing action differs. Added a failing regression, then fixed exact-tuple removal/reinsertion by exact semantic specification (not mutable numbered-list positions); unrelated source/interface/direction/family rules are retained. Skipped insertion now fails explicitly.

## Final local results

- `go test -race -coverprofile=... ./...`: passed; native macOS total statement coverage 81.1% (was 35.4%).
- `go vet ./...` and Linux amd64 vet: passed.
- Linux/macOS amd64/arm64 release builds: passed.
- Installer matching/tampered/missing SHA256 tests: passed without system writes.
- Linux IPv4/IPv6 proc address and ss process parsing: isolated portable fixture test passed.
- Native CLI smoke test correctly exits 1 when no firewall is available, rather than reporting successful deny.
- Shell syntax and diff whitespace checks passed.
- Real Linux packet paths, Docker/UFW service reloads and reboot behavior are not executed on this Mac; use `scripts/test-linux-integration.sh` and `docs/testing.md` on an empty Linux systemd VM before publishing a release.
