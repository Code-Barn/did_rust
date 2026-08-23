# Security Hardening Strategy

Operational security invariants for the `did_rust` core library and every
service that consumes it. `did_rust` powers low-level cryptographic
operations and serialization across `iyou_idp`, `iyou_home`, and
`iyou_mobile`. Any divergence in *which* `did_rust` commit a consumer builds
against causes silent serialization mismatch and handshake failures between
those services.

---

## SEC-003: did_rust Submodule Alignment

### Threat model

`did_rust` is consumed simultaneously as git submodules and as a Cargo path
dependency. Nothing in plain git stops one parent from pinning commit `A`
while another pins commit `B`, or a developer's local checkout from sitting
at `C`. Because FFI structs, proof serialization, and JSON envelopes are
versioned only implicitly by commit, mixed versions produce:

- VC/VP proofs that verify in one consumer and fail in another,
- DID documents that serialize differently across services,
- OIDC/PKCE handshake failures between `iyou_idp` and `iyou_home`,
- failures that appear "random" because each machine built a different hash.

### Consumption matrix (audited 2026-08)

| Site | Repository path | Mechanism | Effective commit source |
|------|-----------------|-----------|-------------------------|
| `iyou_idp` | `iyou_idp/crates/did_rust` | git submodule (`branch = main`) | recorded gitlink in parent HEAD |
| `iyou_home` | `iyou_home/libs/did_rust` | git submodule | recorded gitlink in parent HEAD |
| `iyou_mobile` | `src-tauri/Cargo.toml` → `../../did_rust` | Cargo path dependency | working-copy HEAD of canonical checkout |

The mobile path dependency always tracks whatever the local `did_rust`
checkout currently has checked out, which makes it the most likely source of
divergence.

### Invariants

**INV-1 (single-commit parity).** At any release or deployment boundary,
`iyou_idp`, `iyou_home`, and `iyou_mobile` must resolve the exact same
`did_rust` commit, and that commit must equal the canonical checkout's HEAD.

**INV-2 (no orphaned pins).** A push to `did_rust` must never make a commit
that any consumer still pins unreachable (history rewrites, branch deletes).
Orphaned pins break fresh clones of the parents.

### Enforcement layers

1. **Pre-push hook** (`scripts/githooks/pre-push`, install with
   `scripts/install_hooks.sh`). Runs the checker in `--pre-push <sha>` mode:
   every consumer-resolved commit must be an ancestor of (or equal to) the
   commit being pushed. Blocks force-pushes and rewrites from orphaning live
   pins. It deliberately does *not* require full parity at push time so the
   documented staged-rollout flow below stays possible.
2. **CI parity workflow** (`.github/workflows/parity.yml`).
   - `selftest` job: runs `scripts/test_check_did_submodules.sh` on hosted
     runners; validates guard logic on every PR/push.
   - `parity-live` job: runs the real check against the LAN workspace on the
     self-hosted runner. Enforced for **release publishes**, manual dispatch
     with `enforce=true`, or when repository variable `PARITY_ENFORCE=true`.
3. **Deployment gate.** Cluster/deployment runners must invoke the checker as
   the first pipeline step (template included at the bottom of
   `parity.yml`). Non-zero exit blocks the deploy.

### The checker

```bash
bash scripts/check_did_submodules.sh                 # strict parity check
bash scripts/check_did_submodules.sh --json          # machine-readable report
bash scripts/check_did_submodules.sh --tolerate-canonical-ahead   # staged rollout
bash scripts/check_did_submodules.sh --pre-push SHA  # hook mode
bash scripts/test_check_did_submodules.sh            # fixture self-test
```

Exit codes: `0` aligned · `1` parity violation · `2` environment/usage error.

Options `--root PATH` (workspace root containing the consumer repos) and
`--canonical PATH` (canonical did_rust checkout) plus env vars
`PARITY_ROOT` / `PARITY_CANONICAL_DIR` adapt the script to non-standard
layouts such as CI runners.

### Canonical synchronized-update procedure

When `did_rust` changes, propagate atomically:

```bash
# 1. In did_rust: land + publish the change, then run the pre-push gate.
cd CODE_BASE/did_rust && git push            # pre-push hook validates reachability

# 2. In each submodule consumer: fast-forward the pin to did_rust main.
git -C CODE_BASE/iyou_idp  submodule update --remote --merge crates/did_rust
git -C CODE_BASE/iyou_home submodule update --remote --merge libs/did_rust

# 3. iyou_mobile follows automatically after updating the local checkout:
git -C CODE_BASE/did_rust pull

# 4. Verify full alignment before committing the pointer bumps.
bash CODE_BASE/did_rust/scripts/check_did_submodules.sh

# 5. Commit + push the bumped gitlinks in iyou_idp / iyou_home.
git -C CODE_BASE/iyou_idp  add crates/did_rust && git -C CODE_BASE/iyou_idp  commit -m "chore: bump did_rust"
git -C CODE_BASE/iyou_home add libs/did_rust && git -C CODE_BASE/iyou_home commit -m "chore: bump did_rust"
```

During step 4 the workspace is intentionally misaligned; pass
`--tolerate-canonical-ahead` if you need a green check mid-rollout (it still
requires all three consumers to agree with *each other*).

### Release checklist

- [ ] `bash scripts/check_did_submodules.sh` exits `0`
- [ ] `cargo test` green at the pinned commit
- [ ] `parity-live` CI job green for the release tag
- [ ] no consumer reports worktree ≠ recorded pin (checker fails loudly otherwise)

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `consumers resolve to DIFFERENT did_rust commits` | submodule pins out of sync with the path dependency | run the synchronized-update procedure above |
| `checked-out worktree ... differs from committed submodule pin` | someone checked out a different ref inside the submodule | `git -C <parent> submodule update <path>` |
| `submodule not initialized` | fresh clone without submodule init | `git -C <parent> submodule update --init <path>` |
| `... NOT reachable from pushed commit` | history rewrite orphaned a consumer pin | restore original history or re-pin consumers before pushing |
| `canonical did_rust checkout is ... behind` | local dev checkout older than what ships | `git -C CODE_BASE/did_rust pull` |
| CI cannot find consumers | hosted runner has no LAN workspace | run `selftest` job only; schedule `parity-live` on the self-hosted runner |

### Known drift remediation (2026-08 audit)

At the time this control was introduced the live workspace was already in
violation: both submodules pinned `cb3deb0b` while the canonical checkout
(and therefore `iyou_mobile`) sat at `6b554d9`. Remediate with:

```bash
git -C CODE_BASE/did_rust pull                                # canonical -> 6b554d9
git -C CODE_BASE/iyou_idp  submodule update --remote --merge crates/did_rust
git -C CODE_BASE/iyou_home submodule update --remote --merge libs/did_rust
bash CODE_BASE/did_rust/scripts/check_did_submodules.sh       # must print PARITY OK
git -C CODE_BASE/iyou_idp  add crates/did_rust && git -C CODE_BASE/iyou_idp  commit -m "security(SEC-003): align did_rust pin"
git -C CODE_BASE/iyou_home add libs/did_rust && git -C CODE_BASE/iyou_home commit -m "security(SEC-003): align did_rust pin"
```
