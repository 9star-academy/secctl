# Ubuntu SSH socket port compatibility implementation plan

**Goal:** Switch and roll back SSH ports on Ubuntu 26.04 socket activation, then publish v1.0.2-rc.2 for acceptance.

**Architecture:** Keep classic sshd reloads. For an active Ubuntu ssh.socket, snapshot its original TCP listeners in the independent rollback state, require ssh.service KillMode=process, regenerate systemd configuration, check that the generated listeners match the requested port, then stop/start the service and socket together. Recovery regenerates the original listeners from the restored SSH configuration and verifies them before marking recovery complete. Do not add drop-ins or change enablement.

**Tech stack:** Existing Go standard library, systemd, OpenSSH, ss, GitHub Actions Ubuntu 26.04.

The user explicitly requested fixing this compatibility issue and publishing a new acceptance version. The scope and acceptance requirements are approved by that request; routine implementation choices proceed without another approval round.

## Design choices

1. **Use the existing generator (chosen):** smallest system change; respects existing ListenAddress/AddressFamily and custom units. Reject mismatched generated listeners before stopping SSH.
2. Add a permanent socket override: adds another configuration authority and rollback files; unnecessary for Ubuntu 26.04.
3. Disable socket activation: changes administrator policy and avoids rather than fixes compatibility; rejected.

## Tasks and checks

1. Add failing socket tests in `internal/ssh/socket_test.go`: regenerated listeners, classic fallback, custom KillMode rejection, generated port mismatch, restart failure, persisted independent rollback and retry. Run `go test ./internal/ssh` and observe failure before implementation.
2. Add `internal/ssh/socket.go`; extend `internal/ssh/manager.go` and `rollback.go` with socket detection and disk-persisted listener recovery. Preserve original confirmation and timer behavior. Re-run focused tests.
3. Extend `scripts/test-linux-integration.sh` and add a dedicated real SSH lifecycle script covering confirmed login, timeout, Ctrl+C and HUP on socket and classic service modes. Add an Ubuntu 26.04 hosted-VM CI job; require actual SSH authentication and original-port restoration, not only configuration comparisons.
4. Update `README.md`, `docs/testing.md`, Ubuntu acceptance commands and `docs/releases/v1.0.2-rc.2.md` to use the new published version and test socket port changes directly.
5. Run race/coverage tests (target total >=80%), vet, shell/install checks, cross-platform builds, whitespace checks. Commit and push only this change and its acceptance documentation. Wait for Ubuntu 26.04 integration CI before tagging rc.2.
6. Push the new annotated tag; wait for the release workflow; verify prerelease metadata, all four binaries, SHA256SUMS and native version output. Provide the pinned installation command and remaining real-server acceptance boundaries.

## Required behavior

- Active ssh.socket stays enabled/running in socket mode after confirmation or recovery; no permanent unit edits.
- New port must be generated and actually listening, with successful fresh key login in integration tests.
- A pending transaction stores the original socket listeners before any mutation; independent recovery works even when the foreground process is gone and the socket/service is currently stopped.
- Unsafe service KillMode, unsupported socket units or generated port conflicts fail visibly. Failed recovery retains pending state for retry.
- Existing SSH sessions survive the controlled restart under KillMode=process.
- Reboot only after confirmation/recovery; transient rollback timers still do not guarantee recovery across reboot.

## Progress

- [x] Inspect current source, prior release and primary Ubuntu/systemd documentation.
- [x] Select minimal design within the user's authorized fix and release scope.
- [x] Observe failing regression tests, then implement.
- [ ] Pass local verification and Ubuntu 26.04 live-service CI.
- [ ] Publish and verify v1.0.2-rc.2.

## Verification before publication

- Local race/coverage suite and vet passed; aggregate coverage 82.0%.
- Linux/macOS amd64/arm64 builds and installer SHA256 tests passed.
- The first real-service runs exposed transient recovery service collection during confirmation and active/configured socket listener representation differences. Both have reproducing regression tests and fixes.
- Ubuntu 22.04 service and Ubuntu 26.04 socket integration passed on source commit `1e3b098`.
- Real UFW/Docker lifecycle passed on source commit `4ff6688` after fixing missing ufw-user-forward initialization. The combined test now waits for the recovery marker as well as restored file contents, so it cannot check the listener halfway through recovery.
