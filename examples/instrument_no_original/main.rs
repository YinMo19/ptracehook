use ptracehook::{BreakpointMode, BreakpointSpec, HookAction, SessionBuilder, TraceExit};
use std::process::Command;

fn find_calc_add_instruction(binary: &str) -> Result<u64, String> {
    let output = Command::new("objdump")
        .arg("-d")
        .arg("--no-show-raw-insn")
        .arg(binary)
        .output()
        .map_err(|e| format!("failed to run objdump: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "objdump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout =
        String::from_utf8(output.stdout).map_err(|e| format!("invalid objdump output: {e}"))?;
    let mut in_calc = false;

    for line in stdout.lines() {
        let trimmed = line.trim_start();

        if trimmed.ends_with("<calc>:") {
            in_calc = true;
            continue;
        }

        if !in_calc {
            continue;
        }

        if trimmed.ends_with(":") && trimmed.contains('<') && !trimmed.ends_with("<calc>:") {
            break;
        }

        let Some((addr_hex, rest)) = trimmed.split_once(':') else {
            continue;
        };

        let mnemonic = rest.split_whitespace().next().unwrap_or("");
        if mnemonic == "add" {
            let addr = u64::from_str_radix(addr_hex.trim(), 16)
                .map_err(|e| format!("invalid instruction address {addr_hex}: {e}"))?;
            return Ok(addr);
        }
    }

    Err(format!(
        "failed to locate add instruction in calc for {binary}"
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = "examples/instrument_no_original/app";
    let calc_add = find_calc_add_instruction(target)?;

    let mut session = SessionBuilder::spawn(target).args(["4", "5"]).build()?;

    let spec = BreakpointSpec {
        address: calc_add,
        mode: BreakpointMode::SkipOriginal,
        name: Some("calc_add_skip".to_string()),
    };

    session.add_breakpoint(
        spec,
        Box::new(|ctx| {
            ctx.regs.rax = 99;
            Ok(HookAction::Continue)
        }),
    )?;

    match session.run()? {
        TraceExit::Exited(0) => Ok(()),
        other => Err(format!("unexpected trace exit: {other:?}").into()),
    }
}
