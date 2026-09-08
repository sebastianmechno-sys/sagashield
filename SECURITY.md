# Security Policy — sagashield

## Threat Model & Architecture Assumptions

**Scope (v0.1).** The `SecurityGuard` (`src/security/`) is an **application-level,
lexical + whitelist** boundary. It is designed as one defense-in-depth layer:
it makes whole classes of tool-level attacks (path traversal, sensitive-file
access, network exfiltration to unlisted domains) fail closed *before* the FSM
check, the WAL write, or any side effect.

**Explicit non-assumptions.** At v0.1 the guard does **not** claim:

- **TOCTOU safety.** `check_path_access` validates a path, the tool uses it
  afterwards. A concurrent rename/symlink swap in between (time-of-check to
  time-of-use) can defeat any userspace check. Mitigation planned: OS-level
  confinement (below).
- **Symlink-race immunity.** Existing symlinks are resolved best-effort
  (`canonical_if_exists`) and escapes are denied, but races remain possible
  on a hostile filesystem.
- **Kernel-enforced isolation.** There is no seccomp/Landlock profile, no
  AppContainer, no container boundary. A compromised *process* (as opposed to
  a confused *agent*) is out of scope for this layer.
- **8.3 short-name resolution.** Components matching the tilde pattern
  (`ENV~1`) are *blocked conservatively*, which may over-block legitimate
  names containing `~<digit>`. This tradeoff is intentional and documented.

**Planned confinement.** Linux: Landlock ABI (unprivileged path sandboxing
per saga). Windows: AppContainer integrity levels for tool workers. Until
then, run untrusted workloads with least privilege at the OS level too.

**Cryptography.** None in scope: the WAL is an integrity *log*, not an
authenticated ledger (hash-chained audit log is on the roadmap, Fase 4+).

## Python GIL Concurrency Boundary

Python tools registered through the PyO3 bridge (`src/python.rs`) execute
their `execute`/`compensate` callbacks under the **Global Interpreter Lock**:
under concurrent multi-saga load the Python callables are effectively
serialized by the GIL, while the Rust side (WAL, FSM, dispatcher) stays fully
parallel. Consequences and guidance:

- Throughput of *Python-implemented* tools does not scale with Tokio worker
  count; CPU-bound Python callbacks serialize. I/O-bound callbacks that
  release the GIL (native extensions) are unaffected.
- Never call back into the kernel from inside a tool callback (the Tokio
  runtime is blocked waiting for the callback to return).
- For extreme throughput, prefer native Rust tools, or shard Python tools
  across separate OS processes (one interpreter per worker) instead of
  threads sharing one kernel.

## Network Egress Enforcement Scope

The domain whitelist (`check_network_access`, enforced at Step-0 for the
`url`/`domain`/`endpoint` params) validates **application-level strings
handed to tools** — i.e. it stops a *confused agent* from being talked into
contacting `evil-exfil.example.com`. It does **not** replace OS-level egress
control: a natively compromised/malicious tool process can open raw sockets
that never pass through the guard. For hostile-code scenarios use a
transparent proxy or an eBPF socket filter (planned) in front of tool
workers; treat the whitelist as prompt-injection defense, not as a firewall.

## Hardening already implemented

| Attack | Mitigation (`src/security/policy.rs`) |
|---|---|
| `../../` traversal, absolute outsiders | Lexical normalization + strict `starts_with` on allowed roots |
| Symlink pointing outside | Best-effort canonicalization + re-check (`PathTraversalDetected`) |
| `.env␣` / `foo.txt.` Win32 normalization | Trailing dots/spaces stripped before screening |
| `ENV~1` 8.3 short names | Tilde+digit components blocked (`BlockedFileAccess`) |
| `file.txt:evil` ADS | `:` in real filename components blocked |
| `CON`/`NUL`/`COM1` devices | Reserved-name stems blocked (any component) |
| `api.stripe.com.attacker.com`, `user@host` tricks | Authority parsing + exact-or-subdomain whitelist match |
| Octal/hex/decimal IP literals | Never whitelisted (`UnauthorizedNetworkAccess`) |
| Fuzzed garbage / null bytes | 1.300+ hostile inputs in `security_fuzz_test`; libFuzzer targets in `fuzz/` |

## Responsible disclosure

Do **not** open a public issue for a suspected vulnerability. Instead:

1. Go to the GitHub repository → **Security** tab → **Report a vulnerability**
   (private security advisory). Include: affected version/commit, steps to
   reproduce (minimal `check_path_access` / `check_network_access` input or
   MCP transcript), and impact assessment.
2. Allow up to **90 days** for a fix and coordinated disclosure before going
   public. We will credit reporters in the advisory unless anonymity is
   requested.
3. Scope notes: sandbox escapes with `Ok()` outside allowed roots, whitelist
   bypasses, and FSM/WAL bypasses are in scope. Social engineering of
   operators and vulnerabilities in third-party crates are out of scope
   (report those upstream).

## Operator guidance

- Keep `allowed_root_paths` to dedicated, non-shared directories.
- Never add dotfiles, VCS metadata, or key material patterns to an allowlist;
  the default blocklist covers `.env`, `.git`, `id_rsa`, `id_ed25519`,
  `credentials` — extend it for your secrets layout.
- Treat `RECOVERED_WITH_DLQ` sessions and any `UNRESOLVED` DLQ entry as
  incidents: a compensation failed and human review is required
  (inspect via the `kernel_list_dlq` MCP tool).
