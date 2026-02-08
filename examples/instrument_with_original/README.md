# instrument_with_original

Demonstrates `BreakpointMode::ExecuteOriginal`.

The tracer locates the `add` instruction inside `calc`, sets registers to produce
`40 + 2`, then executes the original `add` instruction.

Expected output:

```text
calc(1, 2) = 42
```

## Run

```bash
cc -O0 -fno-omit-frame-pointer -no-pie examples/instrument_with_original/target.c -o examples/instrument_with_original/app
cargo run --example instrument_with_original
```
