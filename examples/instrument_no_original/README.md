# instrument_no_original

Demonstrates `BreakpointMode::SkipOriginal`.

The tracer breaks at `calc` entry, sets return register to `99`, and skips the original function body.
Expected output:

```text
calc(4, 5) = 99
```

## Run

```bash
cc -O0 -fno-omit-frame-pointer -no-pie examples/instrument_no_original/target.c -o examples/instrument_no_original/app
cargo run --example instrument_no_original
```
