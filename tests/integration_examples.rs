#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::path::Path;
use std::process::Command;

fn build_target(source: &str, output: &str) {
    let status = Command::new("cc")
        .args([
            "-O0",
            "-fno-omit-frame-pointer",
            "-fno-inline",
            "-no-pie",
            source,
            "-o",
            output,
        ])
        .status()
        .expect("failed to run cc");

    assert!(status.success(), "cc failed for {source}");
}

fn run_example(example: &str) -> String {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--example", example]);

    let output = cmd.output().expect("failed to run cargo example");
    assert!(
        output.status.success(),
        "example failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("stdout not utf8")
}

#[test]
fn instrument_with_original_example_smoke() {
    let app = "examples/instrument_with_original/app";
    if Path::new(app).exists() {
        let _ = std::fs::remove_file(app);
    }

    build_target("examples/instrument_with_original/target.c", app);
    let stdout = run_example("instrument_with_original");
    assert!(stdout.contains("calc(1, 2) = 42"), "stdout was: {stdout}");
}

#[test]
fn instrument_no_original_example_smoke() {
    let app = "examples/instrument_no_original/app";
    if Path::new(app).exists() {
        let _ = std::fs::remove_file(app);
    }

    build_target("examples/instrument_no_original/target.c", app);
    let stdout = run_example("instrument_no_original");
    assert!(stdout.contains("calc(4, 5) = 99"), "stdout was: {stdout}");
}
