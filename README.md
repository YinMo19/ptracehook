# ptracehook

`ptracehook` is an out-of-process runtime hook framework for Linux targets.

Current release line (`0.2.x`) supports both Linux architectures:

- Linux `x86_64`: usable runtime implementation (spawn/attach + software breakpoints + callbacks)
- Linux `aarch64`: usable runtime implementation (spawn/attach + software breakpoints + callbacks)

Unlike in-process signal/trap hook crates, `ptracehook` is designed for scenarios where preload-based injection is unavailable (for example, statically linked executables).

## Current status

- Public API is stable for the current release line and Linux runtime core is implemented.
- Linux `x86_64` now includes:
  - spawn/attach session flow,
  - software breakpoint install/restore/reinsert loop,
  - callback-based hook dispatch,
  - register get/set,
  - remote memory read/write helpers.
- Linux `aarch64` runtime now includes the same core flow as `x86_64` (spawn/attach, breakpoints, callbacks, register/memory helpers).
- Detailed implementation plan and API contract are documented in `AGENT.md`.

## Scope

- Primary MVP targets: `linux x86_64` and `linux aarch64`
- Primary runtime primitive: `ptrace` (`PTRACE_TRACEME` / `PTRACE_ATTACH` / breakpoint + single-step loop)

## Examples

- `examples/instrument_with_original`
- `examples/instrument_no_original`

Example quick run (Linux `x86_64` / `aarch64`):

```bash
cc -O0 -fno-omit-frame-pointer -no-pie examples/instrument_with_original/target.c -o examples/instrument_with_original/app
cargo run --example instrument_with_original
```

## CI

CI workflow is at `.github/workflows/ci.yml` and currently includes:

- native Linux `x86_64` job on `ubuntu-24.04`:
  - fmt/check/clippy/test
  - runtime smoke examples
- native Linux `aarch64` job on `ubuntu-24.04-arm`:
  - check/clippy/test
  - examples build
  - runtime smoke examples
