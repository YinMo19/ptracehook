use crate::error::PtraceHookError;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use iced_x86::{Decoder, DecoderOptions};
use std::collections::HashMap;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::ffi::CString;
use std::ffi::OsString;
use std::fmt;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub type Pid = i32;
pub type BreakpointId = u64;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const INT3_OPCODE: u8 = 0xCC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointMode {
    ExecuteOriginal,
    SkipOriginal,
}

#[derive(Debug, Clone)]
pub struct BreakpointSpec {
    pub address: u64,
    pub mode: BreakpointMode,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAction {
    Continue,
    ContinueWithSignal(i32),
    SingleStepThenContinue,
    Detach,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    BreakpointHit { id: BreakpointId, address: u64 },
    SignalStop { signal: i32 },
    Exited { code: i32 },
    Signaled { signal: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceExit {
    Exited(i32),
    Signaled(i32),
    Detached,
    Killed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegistersX86_64 {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
}

#[derive(Debug, Clone)]
pub struct HookContext {
    pub pid: Pid,
    pub breakpoint_id: BreakpointId,
    pub address: u64,
    pub regs: RegistersX86_64,
}

pub type HookCallback =
    Box<dyn FnMut(&mut HookContext) -> Result<HookAction, PtraceHookError> + Send + 'static>;

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub exit_kill: bool,
    pub pass_through_non_trap_signals: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            exit_kill: true,
            pass_through_non_trap_signals: true,
        }
    }
}

#[derive(Debug, Clone)]
enum LaunchKind {
    Spawn { path: PathBuf, args: Vec<OsString> },
    Attach { pid: Pid },
}

#[derive(Debug, Clone)]
pub struct SessionBuilder {
    launch: LaunchKind,
    options: SessionOptions,
}

impl SessionBuilder {
    pub fn spawn(path: impl Into<PathBuf>) -> Self {
        Self {
            launch: LaunchKind::Spawn {
                path: path.into(),
                args: Vec::new(),
            },
            options: SessionOptions::default(),
        }
    }

    pub fn attach(pid: Pid) -> Self {
        Self {
            launch: LaunchKind::Attach { pid },
            options: SessionOptions::default(),
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        if let LaunchKind::Spawn { args, .. } = &mut self.launch {
            args.push(arg.into());
        }
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        if let LaunchKind::Spawn {
            args: launch_args, ..
        } = &mut self.launch
        {
            launch_args.extend(args.into_iter().map(Into::into));
        }
        self
    }

    pub fn options(mut self, options: SessionOptions) -> Self {
        self.options = options;
        self
    }

    pub fn build(self) -> Result<TraceSession, PtraceHookError> {
        match &self.launch {
            LaunchKind::Spawn { path, .. } => {
                if path.as_os_str().is_empty() {
                    return Err(PtraceHookError::BuildError("spawn path is empty"));
                }
            }
            LaunchKind::Attach { pid } => {
                if *pid <= 0 {
                    return Err(PtraceHookError::InvalidPid(*pid));
                }
            }
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = self;
            Err(PtraceHookError::UnsupportedPlatform)
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            Ok(TraceSession {
                launch: self.launch,
                options: self.options,
                next_breakpoint_id: 1,
                state: SessionState::Created,
                traced_pid: None,
                breakpoints_by_id: HashMap::new(),
                breakpoint_by_addr: HashMap::new(),
                global_original_bytes: HashMap::new(),
            })
        }
    }
}

#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(dead_code)
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Created,
    Running,
    Exited,
    Detached,
    Killed,
}

#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(dead_code)
)]
struct BreakpointEntry {
    id: BreakpointId,
    spec: BreakpointSpec,
    callback: HookCallback,
    installed: bool,
    original_byte: Option<u8>,
}

pub struct TraceSession {
    launch: LaunchKind,
    options: SessionOptions,
    next_breakpoint_id: BreakpointId,
    state: SessionState,
    traced_pid: Option<Pid>,
    breakpoints_by_id: HashMap<BreakpointId, BreakpointEntry>,
    breakpoint_by_addr: HashMap<u64, BreakpointId>,
    global_original_bytes: HashMap<u64, u8>,
}

impl fmt::Debug for TraceSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceSession")
            .field("launch", &self.launch)
            .field("options", &self.options)
            .field("next_breakpoint_id", &self.next_breakpoint_id)
            .field("state", &self.state)
            .field("traced_pid", &self.traced_pid)
            .field("breakpoint_count", &self.breakpoints_by_id.len())
            .finish()
    }
}

impl TraceSession {
    pub fn add_breakpoint(
        &mut self,
        spec: BreakpointSpec,
        callback: HookCallback,
    ) -> Result<BreakpointId, PtraceHookError> {
        if spec.address == 0 {
            return Err(PtraceHookError::InvalidAddress(spec.address));
        }

        if self.breakpoint_by_addr.contains_key(&spec.address) {
            return Err(PtraceHookError::BreakpointAddressInUse(spec.address));
        }

        let id = self.next_breakpoint_id;
        self.next_breakpoint_id = self.next_breakpoint_id.saturating_add(1);

        #[cfg_attr(
            not(all(target_os = "linux", target_arch = "x86_64")),
            allow(unused_mut)
        )]
        let mut entry = BreakpointEntry {
            id,
            spec,
            callback,
            installed: false,
            original_byte: None,
        };

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if self.state == SessionState::Running {
                let pid = self
                    .traced_pid
                    .ok_or(PtraceHookError::InvalidLifecycle("missing traced pid"))?;
                let original = self.install_breakpoint_for_pid_x86_64(pid, entry.spec.address)?;
                entry.installed = true;
                entry.original_byte = Some(original);
                self.global_original_bytes
                    .entry(entry.spec.address)
                    .or_insert(original);
            }
        }

        self.breakpoint_by_addr.insert(entry.spec.address, id);
        self.breakpoints_by_id.insert(id, entry);
        Ok(id)
    }

    pub fn remove_breakpoint(&mut self, id: BreakpointId) -> Result<(), PtraceHookError> {
        let entry = self
            .breakpoints_by_id
            .remove(&id)
            .ok_or(PtraceHookError::BreakpointNotFound(id))?;

        self.breakpoint_by_addr.remove(&entry.spec.address);

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            if entry.installed {
                let pid = self
                    .traced_pid
                    .ok_or(PtraceHookError::InvalidLifecycle("missing traced pid"))?;
                Self::restore_original_byte_x86_64(pid, entry.spec.address, entry.original_byte)?;
            }
        }

        self.global_original_bytes.remove(&entry.spec.address);
        Ok(())
    }

    pub fn run(&mut self) -> Result<TraceExit, PtraceHookError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            return self.run_linux_x86_64();
        }

        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            return Err(PtraceHookError::NotImplemented(
                "linux aarch64 backend is planned but not implemented yet",
            ));
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Err(PtraceHookError::UnsupportedPlatform)
        }
    }

    pub fn read_bytes(&mut self, remote_addr: u64, len: usize) -> Result<Vec<u8>, PtraceHookError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let pid = self.traced_pid.ok_or(PtraceHookError::InvalidLifecycle(
                "session has no traced pid",
            ))?;
            return read_bytes_x86_64(pid, remote_addr, len);
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (remote_addr, len);
            Err(PtraceHookError::NotImplemented(
                "read_bytes is only implemented on linux x86_64",
            ))
        }
    }

    pub fn write_bytes(&mut self, remote_addr: u64, data: &[u8]) -> Result<(), PtraceHookError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let pid = self.traced_pid.ok_or(PtraceHookError::InvalidLifecycle(
                "session has no traced pid",
            ))?;
            return write_bytes_x86_64(pid, remote_addr, data);
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (remote_addr, data);
            Err(PtraceHookError::NotImplemented(
                "write_bytes is only implemented on linux x86_64",
            ))
        }
    }

    pub fn get_regs(&mut self) -> Result<RegistersX86_64, PtraceHookError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let pid = self.traced_pid.ok_or(PtraceHookError::InvalidLifecycle(
                "session has no traced pid",
            ))?;
            let raw = ptrace_getregs_x86_64(pid)?;
            return Ok(RegistersX86_64::from(raw));
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(PtraceHookError::NotImplemented(
                "get_regs is only implemented on linux x86_64",
            ))
        }
    }

    pub fn set_regs(&mut self, regs: &RegistersX86_64) -> Result<(), PtraceHookError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let pid = self.traced_pid.ok_or(PtraceHookError::InvalidLifecycle(
                "session has no traced pid",
            ))?;
            let mut raw = ptrace_getregs_x86_64(pid)?;
            apply_registers_x86_64(&mut raw, regs);
            return ptrace_setregs_x86_64(pid, &raw);
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = regs;
            Err(PtraceHookError::NotImplemented(
                "set_regs is only implemented on linux x86_64",
            ))
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl TraceSession {
    fn run_linux_x86_64(&mut self) -> Result<TraceExit, PtraceHookError> {
        if self.state != SessionState::Created {
            return Err(PtraceHookError::InvalidLifecycle(
                "run can only be called once on a fresh session",
            ));
        }

        let (pid, spawn_mode) = match &self.launch {
            LaunchKind::Spawn { path, args } => (spawn_tracee_x86_64(path, args)?, true),
            LaunchKind::Attach { pid } => {
                ptrace_attach_x86_64(*pid)?;
                (*pid, false)
            }
        };

        self.traced_pid = Some(pid);

        let first_stop = wait_for_specific_pid_x86_64(pid)?;
        if !first_stop.stopped {
            return Err(PtraceHookError::InvalidLifecycle(
                "tracee did not stop after spawn/attach",
            ));
        }

        if spawn_mode {
            ptrace_continue_x86_64(pid, 0)?;

            loop {
                let stop = wait_for_specific_pid_x86_64(pid)?;

                if stop.exited {
                    self.state = SessionState::Exited;
                    return Ok(TraceExit::Exited(stop.exit_code.unwrap_or_default()));
                }

                if stop.signaled {
                    self.state = SessionState::Exited;
                    return Ok(TraceExit::Signaled(stop.term_signal.unwrap_or_default()));
                }

                if !stop.stopped {
                    continue;
                }

                if stop.stop_signal == Some(libc::SIGTRAP) {
                    break;
                }

                let forward_signal = if self.options.pass_through_non_trap_signals {
                    stop.stop_signal.unwrap_or(0)
                } else {
                    0
                };
                ptrace_continue_x86_64(pid, forward_signal)?;
            }
        }

        self.configure_ptrace_options_x86_64(pid)?;
        self.install_all_breakpoints_x86_64(pid)?;
        self.state = SessionState::Running;

        ptrace_continue_x86_64(pid, 0)?;

        loop {
            let stop = wait_for_specific_pid_x86_64(pid)?;

            if stop.exited {
                self.restore_all_breakpoints_x86_64(pid);
                self.state = SessionState::Exited;
                return Ok(TraceExit::Exited(stop.exit_code.unwrap_or_default()));
            }

            if stop.signaled {
                self.restore_all_breakpoints_x86_64(pid);
                self.state = SessionState::Exited;
                return Ok(TraceExit::Signaled(stop.term_signal.unwrap_or_default()));
            }

            if !stop.stopped {
                continue;
            }

            let signal = stop.stop_signal.unwrap_or_default();

            if signal == libc::SIGTRAP {
                match self.handle_sigtrap_x86_64(pid)? {
                    RunDecision::Continue(sig) => {
                        ptrace_continue_x86_64(pid, sig)?;
                    }
                    RunDecision::Detach => {
                        self.restore_all_breakpoints_x86_64(pid);
                        ptrace_detach_x86_64(pid, 0)?;
                        self.state = SessionState::Detached;
                        return Ok(TraceExit::Detached);
                    }
                    RunDecision::Kill => {
                        self.restore_all_breakpoints_x86_64(pid);
                        ptrace_kill_x86_64(pid)?;
                        self.state = SessionState::Killed;
                        return Ok(TraceExit::Killed);
                    }
                }
                continue;
            }

            if signal == (libc::SIGTRAP | 0x80) {
                ptrace_continue_x86_64(pid, 0)?;
                continue;
            }

            let forward_signal = if self.options.pass_through_non_trap_signals {
                signal
            } else {
                0
            };
            ptrace_continue_x86_64(pid, forward_signal)?;
        }
    }

    fn configure_ptrace_options_x86_64(&self, pid: Pid) -> Result<(), PtraceHookError> {
        let mut options = libc::PTRACE_O_TRACESYSGOOD as libc::c_ulong;
        if self.options.exit_kill {
            options |= libc::PTRACE_O_EXITKILL as libc::c_ulong;
        }
        ptrace_setoptions_x86_64(pid, options)
    }

    fn install_all_breakpoints_x86_64(&mut self, pid: Pid) -> Result<(), PtraceHookError> {
        let ids: Vec<BreakpointId> = self.breakpoints_by_id.keys().copied().collect();

        for id in ids {
            let address = self
                .breakpoints_by_id
                .get(&id)
                .ok_or(PtraceHookError::BreakpointNotFound(id))?
                .spec
                .address;

            let original = self.install_breakpoint_for_pid_x86_64(pid, address)?;

            if let Some(entry) = self.breakpoints_by_id.get_mut(&id) {
                entry.installed = true;
                entry.original_byte = Some(original);
            }

            self.global_original_bytes
                .entry(address)
                .or_insert(original);
        }

        Ok(())
    }

    fn install_breakpoint_for_pid_x86_64(
        &self,
        pid: Pid,
        address: u64,
    ) -> Result<u8, PtraceHookError> {
        let mut word = ptrace_peek_word_x86_64(pid, address)?;
        let mut bytes = word.to_ne_bytes();
        let original = bytes[0];
        bytes[0] = INT3_OPCODE;
        word = libc::c_long::from_ne_bytes(bytes);
        ptrace_poke_word_x86_64(pid, address, word)?;
        Ok(original)
    }

    fn restore_original_byte_x86_64(
        pid: Pid,
        address: u64,
        original_byte: Option<u8>,
    ) -> Result<(), PtraceHookError> {
        let Some(original) = original_byte else {
            return Ok(());
        };

        let mut word = ptrace_peek_word_x86_64(pid, address)?;
        let mut bytes = word.to_ne_bytes();
        bytes[0] = original;
        word = libc::c_long::from_ne_bytes(bytes);
        ptrace_poke_word_x86_64(pid, address, word)
    }

    fn reinsert_breakpoint_x86_64(pid: Pid, address: u64) -> Result<(), PtraceHookError> {
        let mut word = ptrace_peek_word_x86_64(pid, address)?;
        let mut bytes = word.to_ne_bytes();
        bytes[0] = INT3_OPCODE;
        word = libc::c_long::from_ne_bytes(bytes);
        ptrace_poke_word_x86_64(pid, address, word)
    }

    fn restore_all_breakpoints_x86_64(&mut self, pid: Pid) {
        let mut restore_plan = Vec::new();

        for entry in self.breakpoints_by_id.values_mut() {
            if entry.installed {
                restore_plan.push((entry.spec.address, entry.original_byte));
                entry.installed = false;
            }
        }

        for (address, original) in restore_plan {
            let _ = Self::restore_original_byte_x86_64(pid, address, original);
        }
    }

    fn handle_sigtrap_x86_64(&mut self, pid: Pid) -> Result<RunDecision, PtraceHookError> {
        let mut regs = ptrace_getregs_x86_64(pid)?;
        if regs.rip == 0 {
            return Ok(RunDecision::Continue(0));
        }

        let trap_addr = regs.rip.saturating_sub(1);
        let Some(&id) = self.breakpoint_by_addr.get(&trap_addr) else {
            return Ok(RunDecision::Continue(0));
        };

        let original = self
            .breakpoints_by_id
            .get(&id)
            .and_then(|entry| entry.original_byte)
            .or_else(|| self.global_original_bytes.get(&trap_addr).copied());

        Self::restore_original_byte_x86_64(pid, trap_addr, original)?;

        regs.rip = trap_addr;
        ptrace_setregs_x86_64(pid, &regs)?;

        let (action, mode) = {
            let entry = self
                .breakpoints_by_id
                .get_mut(&id)
                .ok_or(PtraceHookError::BreakpointNotFound(id))?;

            let mut hook_ctx = HookContext {
                pid,
                breakpoint_id: entry.id,
                address: trap_addr,
                regs: RegistersX86_64::from(regs),
            };

            let action = (entry.callback)(&mut hook_ctx)?;

            let mut live_regs = ptrace_getregs_x86_64(pid)?;
            apply_registers_x86_64(&mut live_regs, &hook_ctx.regs);
            ptrace_setregs_x86_64(pid, &live_regs)?;
            (action, entry.spec.mode)
        };

        let need_single_step = match mode {
            BreakpointMode::ExecuteOriginal => true,
            BreakpointMode::SkipOriginal => matches!(action, HookAction::SingleStepThenContinue),
        };

        if !need_single_step && matches!(mode, BreakpointMode::SkipOriginal) {
            let step_len = instruction_length_x86_64(pid, trap_addr)?;
            let mut updated = ptrace_getregs_x86_64(pid)?;
            if updated.rip == trap_addr {
                updated.rip = trap_addr
                    .checked_add(step_len as u64)
                    .ok_or(PtraceHookError::InvalidAddress(trap_addr))?;
                ptrace_setregs_x86_64(pid, &updated)?;
            }
            Self::reinsert_breakpoint_x86_64(pid, trap_addr)?;
            return match action {
                HookAction::Continue => Ok(RunDecision::Continue(0)),
                HookAction::ContinueWithSignal(sig) => Ok(RunDecision::Continue(sig)),
                HookAction::SingleStepThenContinue => Ok(RunDecision::Continue(0)),
                HookAction::Detach => Ok(RunDecision::Detach),
                HookAction::Kill => Ok(RunDecision::Kill),
            };
        }

        if need_single_step {
            ptrace_single_step_x86_64(pid, 0)?;
            let step_stop = wait_for_specific_pid_x86_64(pid)?;
            if !step_stop.stopped || step_stop.stop_signal != Some(libc::SIGTRAP) {
                return Err(PtraceHookError::InvalidLifecycle(
                    "single-step did not stop with SIGTRAP",
                ));
            }
            Self::reinsert_breakpoint_x86_64(pid, trap_addr)?;
        }

        if !need_single_step {
            Self::reinsert_breakpoint_x86_64(pid, trap_addr)?;
        }

        match action {
            HookAction::Continue => Ok(RunDecision::Continue(0)),
            HookAction::ContinueWithSignal(sig) => Ok(RunDecision::Continue(sig)),
            HookAction::SingleStepThenContinue => Ok(RunDecision::Continue(0)),
            HookAction::Detach => Ok(RunDecision::Detach),
            HookAction::Kill => Ok(RunDecision::Kill),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
enum RunDecision {
    Continue(i32),
    Detach,
    Kill,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl From<libc::user_regs_struct> for RegistersX86_64 {
    fn from(value: libc::user_regs_struct) -> Self {
        Self {
            r15: value.r15,
            r14: value.r14,
            r13: value.r13,
            r12: value.r12,
            rbp: value.rbp,
            rbx: value.rbx,
            r11: value.r11,
            r10: value.r10,
            r9: value.r9,
            r8: value.r8,
            rax: value.rax,
            rcx: value.rcx,
            rdx: value.rdx,
            rsi: value.rsi,
            rdi: value.rdi,
            rsp: value.rsp,
            rip: value.rip,
            eflags: value.eflags,
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn apply_registers_x86_64(raw: &mut libc::user_regs_struct, regs: &RegistersX86_64) {
    raw.r15 = regs.r15;
    raw.r14 = regs.r14;
    raw.r13 = regs.r13;
    raw.r12 = regs.r12;
    raw.rbp = regs.rbp;
    raw.rbx = regs.rbx;
    raw.r11 = regs.r11;
    raw.r10 = regs.r10;
    raw.r9 = regs.r9;
    raw.r8 = regs.r8;
    raw.rax = regs.rax;
    raw.rcx = regs.rcx;
    raw.rdx = regs.rdx;
    raw.rsi = regs.rsi;
    raw.rdi = regs.rdi;
    raw.rsp = regs.rsp;
    raw.rip = regs.rip;
    raw.eflags = regs.eflags;
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy)]
struct WaitStatus {
    stopped: bool,
    stop_signal: Option<i32>,
    exited: bool,
    exit_code: Option<i32>,
    signaled: bool,
    term_signal: Option<i32>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn wait_for_specific_pid_x86_64(pid: Pid) -> Result<WaitStatus, PtraceHookError> {
    let mut status: libc::c_int = 0;
    let result = unsafe { libc::waitpid(pid, &mut status as *mut libc::c_int, 0) };

    if result < 0 {
        return Err(PtraceHookError::WaitPidFailure {
            errno: current_errno_linux(),
        });
    }

    let stopped = libc::WIFSTOPPED(status);
    let exited = libc::WIFEXITED(status);
    let signaled = libc::WIFSIGNALED(status);

    let stop_signal = if stopped {
        Some(libc::WSTOPSIG(status))
    } else {
        None
    };

    let exit_code = if exited {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    };

    let term_signal = if signaled {
        Some(libc::WTERMSIG(status))
    } else {
        None
    };

    Ok(WaitStatus {
        stopped,
        stop_signal,
        exited,
        exit_code,
        signaled,
        term_signal,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn spawn_tracee_x86_64(path: &PathBuf, args: &[OsString]) -> Result<Pid, PtraceHookError> {
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.is_empty() {
        return Err(PtraceHookError::BuildError("spawn path is empty"));
    }

    let c_path = CString::new(path_bytes)
        .map_err(|_| PtraceHookError::BuildError("spawn path contains interior NUL"))?;

    let mut c_args = Vec::<CString>::with_capacity(args.len() + 1);
    c_args.push(c_path.clone());
    for arg in args {
        let c_arg = CString::new(arg.as_bytes())
            .map_err(|_| PtraceHookError::BuildError("arg contains interior NUL"))?;
        c_args.push(c_arg);
    }

    let mut argv = Vec::<*const libc::c_char>::with_capacity(c_args.len() + 1);
    for c in &c_args {
        argv.push(c.as_ptr());
    }
    argv.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(PtraceHookError::Io("fork failed".to_string()));
    }

    if pid == 0 {
        let _ = ptrace_raw_request_x86_64(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
        unsafe {
            libc::raise(libc::SIGSTOP);
            libc::execv(c_path.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    Ok(pid)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_attach_x86_64(pid: Pid) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_ATTACH,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        std::ptr::null_mut::<libc::c_void>(),
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_detach_x86_64(pid: Pid, signal: i32) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_DETACH,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        signal as usize as *mut libc::c_void,
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_kill_x86_64(pid: Pid) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_KILL,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        std::ptr::null_mut::<libc::c_void>(),
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_continue_x86_64(pid: Pid, signal: i32) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_CONT,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        signal as usize as *mut libc::c_void,
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_single_step_x86_64(pid: Pid, signal: i32) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_SINGLESTEP,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        signal as usize as *mut libc::c_void,
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_setoptions_x86_64(pid: Pid, options: libc::c_ulong) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_SETOPTIONS,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        options as usize as *mut libc::c_void,
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_getregs_x86_64(pid: Pid) -> Result<libc::user_regs_struct, PtraceHookError> {
    let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    ptrace_raw_request_x86_64(
        libc::PTRACE_GETREGS,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        regs.as_mut_ptr() as *mut libc::c_void,
    )?;
    Ok(unsafe { regs.assume_init() })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_setregs_x86_64(pid: Pid, regs: &libc::user_regs_struct) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_SETREGS,
        pid,
        std::ptr::null_mut::<libc::c_void>(),
        regs as *const libc::user_regs_struct as *mut libc::c_void,
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_peek_word_x86_64(pid: Pid, address: u64) -> Result<libc::c_long, PtraceHookError> {
    clear_errno_linux();
    let value = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKDATA,
            pid,
            address as usize as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };

    if value == -1 {
        let errno = current_errno_linux();
        if errno != 0 {
            return Err(PtraceHookError::PtraceFailure {
                operation: "PTRACE_PEEKDATA",
                errno,
            });
        }
    }

    Ok(value)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_poke_word_x86_64(
    pid: Pid,
    address: u64,
    data: libc::c_long,
) -> Result<(), PtraceHookError> {
    ptrace_raw_request_x86_64(
        libc::PTRACE_POKEDATA,
        pid,
        address as usize as *mut libc::c_void,
        data as usize as *mut libc::c_void,
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_raw_request_x86_64(
    request: libc::c_uint,
    pid: Pid,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> Result<libc::c_long, PtraceHookError> {
    clear_errno_linux();
    let result = unsafe { libc::ptrace(request, pid, addr, data) };
    if result == -1 {
        return Err(PtraceHookError::PtraceFailure {
            operation: ptrace_request_name_x86_64(request),
            errno: current_errno_linux(),
        });
    }
    Ok(result)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_request_name_x86_64(request: libc::c_uint) -> &'static str {
    match request {
        libc::PTRACE_TRACEME => "PTRACE_TRACEME",
        libc::PTRACE_PEEKDATA => "PTRACE_PEEKDATA",
        libc::PTRACE_POKEDATA => "PTRACE_POKEDATA",
        libc::PTRACE_CONT => "PTRACE_CONT",
        libc::PTRACE_KILL => "PTRACE_KILL",
        libc::PTRACE_SINGLESTEP => "PTRACE_SINGLESTEP",
        libc::PTRACE_ATTACH => "PTRACE_ATTACH",
        libc::PTRACE_DETACH => "PTRACE_DETACH",
        libc::PTRACE_GETREGS => "PTRACE_GETREGS",
        libc::PTRACE_SETREGS => "PTRACE_SETREGS",
        libc::PTRACE_SETOPTIONS => "PTRACE_SETOPTIONS",
        _ => "PTRACE_UNKNOWN",
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn current_errno_linux() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn clear_errno_linux() {
    unsafe {
        *libc::__errno_location() = 0;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_bytes_x86_64(pid: Pid, remote_addr: u64, len: usize) -> Result<Vec<u8>, PtraceHookError> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let word_size = std::mem::size_of::<libc::c_long>();
    let word_size_u64 = word_size as u64;

    let start = remote_addr;
    let end = remote_addr
        .checked_add(len as u64)
        .ok_or(PtraceHookError::InvalidAddress(remote_addr))?;

    let aligned_start = start & !(word_size_u64 - 1);

    let mut out = Vec::with_capacity(len);
    let mut cursor = aligned_start;

    while cursor < end {
        let word = ptrace_peek_word_x86_64(pid, cursor)?;
        let bytes = word.to_ne_bytes();

        let chunk_start = cursor;
        let chunk_end = cursor + word_size_u64;

        let copy_start = start.max(chunk_start);
        let copy_end = end.min(chunk_end);

        if copy_start < copy_end {
            let offset = (copy_start - chunk_start) as usize;
            let take = (copy_end - copy_start) as usize;
            out.extend_from_slice(&bytes[offset..offset + take]);
        }

        cursor += word_size_u64;
    }

    Ok(out)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_bytes_x86_64(pid: Pid, remote_addr: u64, data: &[u8]) -> Result<(), PtraceHookError> {
    if data.is_empty() {
        return Ok(());
    }

    let word_size = std::mem::size_of::<libc::c_long>();
    let word_size_u64 = word_size as u64;

    let start = remote_addr;
    let end = remote_addr
        .checked_add(data.len() as u64)
        .ok_or(PtraceHookError::InvalidAddress(remote_addr))?;

    let aligned_start = start & !(word_size_u64 - 1);
    let mut cursor = aligned_start;

    while cursor < end {
        let chunk_start = cursor;
        let chunk_end = cursor + word_size_u64;

        let copy_start = start.max(chunk_start);
        let copy_end = end.min(chunk_end);

        if copy_start >= copy_end {
            cursor += word_size_u64;
            continue;
        }

        let mut bytes = ptrace_peek_word_x86_64(pid, cursor)?.to_ne_bytes();

        let src_offset = (copy_start - start) as usize;
        let dst_offset = (copy_start - chunk_start) as usize;
        let take = (copy_end - copy_start) as usize;
        bytes[dst_offset..dst_offset + take].copy_from_slice(&data[src_offset..src_offset + take]);

        let merged = libc::c_long::from_ne_bytes(bytes);
        ptrace_poke_word_x86_64(pid, cursor, merged)?;

        cursor += word_size_u64;
    }

    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn instruction_length_x86_64(pid: Pid, address: u64) -> Result<u8, PtraceHookError> {
    let bytes = read_bytes_x86_64(pid, address, 16)?;
    let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(PtraceHookError::InvalidLifecycle(
            "failed to decode instruction at breakpoint",
        ));
    }

    let len = instruction.len();
    if len == 0 {
        return Err(PtraceHookError::InvalidLifecycle(
            "decoded instruction length is zero",
        ));
    }

    Ok(len as u8)
}
