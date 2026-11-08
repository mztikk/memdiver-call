//! Options for a remote call.

/// A calling convention for a remote function.
///
/// On `x86_64` only [`CallAbi::Auto`] is valid; every other variant is
/// rejected with [`crate::Error::Unsupported`]. On Windows `x86`, `Auto` means
/// `cdecl`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CallAbi {
    /// The platform default: Microsoft `x86_64`, SysV AMD64, or 32-bit
    /// `cdecl`.
    #[default]
    Auto,
    /// 32-bit `cdecl`.
    Cdecl,
    /// 32-bit Windows `stdcall`.
    Stdcall,
    /// 32-bit Windows `thiscall` (`this` in `ECX`).
    Thiscall,
    /// 32-bit Windows `fastcall` (first two arguments in `ECX`/`EDX`).
    Fastcall,
}

/// Options for a remote call.
///
/// The struct is non-exhaustive; use the builder methods to change it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallOptions {
    abi: CallAbi,
    thread: Option<u32>,
}

impl CallOptions {
    /// Creates options with the platform default ABI and no thread override.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the calling convention.
    #[must_use]
    pub fn with_abi(mut self, abi: CallAbi) -> Self {
        self.abi = abi;
        self
    }

    /// Runs the call on a specific Linux thread.
    ///
    /// v1 only supports the main thread, so `tid` must equal the process PID;
    /// any other TID returns [`crate::Error::Unsupported`] before the target is
    /// touched. Windows does not support thread selection in v1 and returns
    /// [`crate::Error::Unsupported`] for any value.
    #[must_use]
    pub fn with_thread(mut self, tid: u32) -> Self {
        self.thread = Some(tid);
        self
    }

    /// Returns the selected calling convention.
    #[must_use]
    pub fn abi(&self) -> CallAbi {
        self.abi
    }

    /// Returns the selected Linux thread, if any.
    #[must_use]
    pub fn thread(&self) -> Option<u32> {
        self.thread
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_platform_auto_and_no_thread() {
        let options = CallOptions::new();
        assert_eq!(options.abi(), CallAbi::Auto);
        assert_eq!(options.thread(), None);
        assert_eq!(CallAbi::default(), CallAbi::Auto);
    }

    #[test]
    fn builder_changes_one_option_at_a_time() {
        let options = CallOptions::new().with_abi(CallAbi::Stdcall).with_thread(7);
        assert_eq!(options.abi(), CallAbi::Stdcall);
        assert_eq!(options.thread(), Some(7));
        assert_eq!(CallOptions::new().with_thread(7).abi(), CallAbi::Auto);
    }
}
