# ptracehook Agent Notes

Last updated: 2026-02-09

## 1) Project Positioning

- Crate: `ptracehook`
- Status: **new scaffold / design-first**
- Goal: build a dedicated out-of-process hook framework on top of `ptrace`, focusing first on Linux `x86_64`.
- Relationship to `sighook`: **complementary, not replacement**.
  - `sighook`: in-process signal/trap patching (BRK/INT3 handler inside target process)
  - `ptracehook`: external tracer model (controller process drives target execution)

### Why separate crate

- Semantic boundary is clear: `sighook` means signal-based in-process hook.
- Runtime model, failure modes, and API ergonomics differ significantly (`fork/attach/waitpid` loop vs in-process callback).
- Keeping them separate reduces conceptual coupling and prevents platform-specific complexity leakage.

## 2) Ecosystem Survey (crates.io quick scan)

The following crates already exist and should be treated as references or potential building blocks:

- `pete` (`0.13.0`): friendly ptrace wrapper.
- `ptrace-do` (`0.1.4`): featureful ptrace interaction library.
- `ptrace` (`0.1.2`): low-level POSIX ptrace bindings.
- `udbg` (`0.3.1`): broader debugging/memory-hacking framework.

### Gap assessment

There are ptrace crates, but there is no obvious crate with a `sighook`-like **hook-centric** API contract (breakpoint registration + callback action contract + deterministic hook event loop tuned for RE/CTF workflows).

Therefore, `ptracehook` is still justified as:

- a focused hook abstraction layer,
- with explicit behavior contracts for breakpoint lifecycle,
- and stable, compact API for scripted reverse workflows.

## 3) Scope and Non-goals (MVP)

### MVP scope (v0.1 -> v0.2)

- Linux `x86_64` only.
- Spawn and attach modes.
- Software breakpoint (`int3`) management.
- Restore-original -> optional single-step -> reinsert flow.
- Register read/write (`user_regs_struct`-aligned abstraction).
- Remote memory read/write helpers.
- Event loop with callback-based hook actions.

### Explicit non-goals (MVP)

- Windows/macOS backend.
- Hardware breakpoint abstraction.
- Full debugger feature parity (symbol server, DWARF stepping, source-level UI).
- Thread-wide advanced scheduling policy beyond basic correctness.

## 4) Public API Draft (current scaffold)

Current scaffold exports these key types from `src/api.rs`:

- `SessionBuilder`
  - `spawn(path)`
  - `attach(pid)`
  - `arg(...)`, `args(...)`
  - `options(...)`
  - `build() -> Result<TraceSession, PtraceHookError>`
- `TraceSession`
  - `add_breakpoint(spec, callback) -> Result<BreakpointId, ...>`
  - `remove_breakpoint(id) -> Result<(), ...>`
  - `run() -> Result<TraceExit, ...>`
  - `read_bytes(...)`, `write_bytes(...)`
  - `get_regs()`, `set_regs(...)`
- `BreakpointSpec`
  - `address`, `mode`, `name`
- `HookCallback` / `HookContext` / `HookAction`
- `RegistersX86_64`

### Hook action contract

`HookAction` is designed to support deterministic control flow decisions:

- `Continue`
- `ContinueWithSignal(i32)`
- `SingleStepThenContinue`
- `Detach`
- `Kill`

### Breakpoint mode contract

- `ExecuteOriginal`: run original instruction (restore byte + single-step + reinsert trap).
- `SkipOriginal`: callback fully controls state transition; default path skips original instruction semantics.

## 5) Internal Architecture Plan

Target module split (planned, not fully implemented):

- `src/lib.rs`: public exports and compile gates.
- `src/session.rs` (or current `api.rs` split later): session lifecycle and state container.
- `src/event_loop.rs`: wait/dispatch loop, signal pass-through rules.
- `src/breakpoint.rs`: install/remove/reinsert breakpoint logic.
- `src/memory.rs`: `PTRACE_PEEKDATA/POKEDATA` helpers with alignment-safe reads/writes.
- `src/regs.rs`: register mapping and conversions.
- `src/error.rs`: typed error model.

### State model requirements

At minimum, `TraceSession` should track:

- launch mode (`spawn` / `attach`),
- active breakpoints map (`BreakpointId -> metadata`),
- original byte cache (`address -> original opcode byte`),
- per-breakpoint callback registry,
- stepping state (`which breakpoint is in single-step recovery`).

## 6) Behavior Invariants (must keep)

- Every installed breakpoint stores original first byte before writing `0xCC`.
- On trap hit:
  1. restore original byte,
  2. set `rip = rip - 1`,
  3. execute callback,
  4. follow callback action,
  5. if needed, single-step and reinsert trap.
- Non-trap stop signals should be forwarded unless policy says otherwise.
- `PTRACE_O_EXITKILL` should be enabled by default for safety.
- Session teardown must attempt best-effort breakpoint restoration.

## 7) Error Model Guidelines

`PtraceHookError` should remain compact and user-facing:

- platform incompatibility,
- invalid pid/address,
- ptrace syscall failure (with operation context + errno),
- internal state errors (missing breakpoint, invalid lifecycle),
- not-implemented placeholders during scaffold stage.

Avoid leaking raw syscall details directly in API unless wrapped with actionable context.

## 8) Roadmap (Detailed Plan)

### Phase 0 — Scaffold (done in this commit)

- Create crate.
- Draft public API shape.
- Add `AGENT.md` contract and implementation roadmap.

### Phase 1 — Core runtime loop

- Implement `spawn` mode.
- Implement `add_breakpoint` + internal table.
- Implement trap dispatch loop with single-thread tracee assumption.
- Implement `run()` for one tracee process.

### Phase 2 — Memory/regs surface

- Implement `read_bytes`/`write_bytes` with unaligned handling.
- Implement register get/set mapping for Linux x86_64.
- Validate callback-controlled register mutation.

### Phase 3 — Attach mode and resilience

- Implement `attach(pid)`.
- Handle already-stopped tracees and signal forwarding.
- Add robust detach/kill/cleanup paths.

### Phase 4 — API hardening

- Add richer `StopReason` reporting and optional observer hooks.
- Add configurable policies (signal pass-through, auto-reinsert behavior).
- Freeze MVP signatures for `0.2.x`.

### Phase 5 — Testing and examples

- Add integration demos:
  - dump-only hook,
  - bypass-style control-flow redirection,
  - oracle-style byte-by-byte solver flow.
- Add regression tests for breakpoint restore and reinsert logic.

## 9) Validation Checklist

Run before merge/release:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
```

Linux x86_64 runtime verification (manual during MVP):

- spawn + breakpoint hit,
- attach + breakpoint hit,
- callback register mutation observed,
- non-trap signal pass-through,
- teardown restores original byte.

## 10) Interop Guidance with sighook

- Keep crate boundaries explicit (`sighook` vs `ptracehook`).
- Shared helper code should move to a separate utility crate only when duplication becomes meaningful.
- Future optional umbrella crate (`hookkit` style) can re-export both backends, but backends remain independent.

## 11) Current Scaffold Limitations

- `TraceSession::run` and many runtime methods currently return `NotImplemented`.
- The scaffold is intentionally API-first to stabilize contracts before low-level ptrace engine work.
- Treat this crate as design baseline for the next implementation iteration.
