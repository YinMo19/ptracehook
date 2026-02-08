use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtraceHookError {
    UnsupportedPlatform,
    InvalidAddress(u64),
    InvalidPid(i32),
    BreakpointNotFound(u64),
    BreakpointAddressInUse(u64),
    BuildError(&'static str),
    InvalidLifecycle(&'static str),
    PtraceFailure { operation: &'static str, errno: i32 },
    WaitPidFailure { errno: i32 },
    NotImplemented(&'static str),
    Io(String),
}

impl fmt::Display for PtraceHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "unsupported platform"),
            Self::InvalidAddress(addr) => write!(f, "invalid address: 0x{addr:x}"),
            Self::InvalidPid(pid) => write!(f, "invalid pid: {pid}"),
            Self::BreakpointNotFound(id) => write!(f, "breakpoint not found: {id}"),
            Self::BreakpointAddressInUse(address) => {
                write!(f, "breakpoint address already in use: 0x{address:x}")
            }
            Self::BuildError(msg) => write!(f, "builder error: {msg}"),
            Self::InvalidLifecycle(msg) => write!(f, "invalid lifecycle: {msg}"),
            Self::PtraceFailure { operation, errno } => {
                write!(f, "ptrace operation failed ({operation}, errno={errno})")
            }
            Self::WaitPidFailure { errno } => write!(f, "waitpid failed (errno={errno})"),
            Self::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
            Self::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl std::error::Error for PtraceHookError {}

impl From<std::io::Error> for PtraceHookError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
