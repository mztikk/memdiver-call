//! Options for a remote call.

use std::time::Duration;

use memdiver::Address;

/// Default bound on the safe-point wait.
pub(crate) const DEFAULT_SAFE_POINT_TIMEOUT: Duration = Duration::from_secs(5);

/// A calling convention for a remote function.
///
/// On `x86_64` only [`CallAbi::Auto`] is valid; every other variant is
/// rejected with [`crate::Error::Unsupported`]. On Windows `x86` and on a
/// 32-bit Windows target under Wine, `Auto` means `cdecl` and the other
/// conventions are available.
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallOptions {
    abi: CallAbi,
    thread: Option<u32>,
    wide_arguments: Vec<usize>,
    safe_point: Option<Address>,
    safe_point_timeout: Duration,
}

impl CallOptions {
    /// Creates options with the platform default ABI, no thread override, and
    /// no safe point.
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

    /// Declares which arguments are 64-bit.
    ///
    /// This applies only to 32-bit `x86` targets: native Windows `x86` and a
    /// 32-bit Windows PE under Wine. Each listed argument occupies two 32-bit
    /// stack slots, low-order first, as the Microsoft x86 ABI requires; this is
    /// how a function with a `uint64_t` parameter is called. Unlisted
    /// arguments must fit in 32 bits.
    ///
    /// Register arguments cannot be wide: the `thiscall` `this` value and the
    /// two `fastcall` register arguments must be 32-bit. A list on any other
    /// target returns [`crate::Error::Unsupported`].
    #[must_use]
    pub fn with_wide_arguments(mut self, indices: &[usize]) -> Self {
        self.wide_arguments = indices.to_vec();
        self
    }

    /// Sets a safe point for a Wine `x86` target.
    ///
    /// A safe point is an instruction address in 32-bit PE code that the
    /// target's main thread reaches regularly, for example the instruction
    /// after `SwapBuffers` returns or a per-frame tick entry. The backend
    /// resumes the thread until a hardware breakpoint at this address fires,
    /// then performs the call; the same breakpoint catches the return.
    ///
    /// Without a safe point, a Wine `x86` call is only attempted when the
    /// thread happens to be stopped in 32-bit mode; a thread stopped in 64-bit
    /// Wine code returns [`crate::Error::Unsupported`]. Safe points are not
    /// accepted by the native-target backends.
    #[must_use]
    pub fn with_safe_point(mut self, address: Address) -> Self {
        self.safe_point = Some(address);
        self
    }

    /// Sets how long to wait for the safe point to be reached.
    ///
    /// The default is five seconds. This bound applies only to the wait for
    /// the safe point; the call itself has no timeout.
    #[must_use]
    pub fn with_safe_point_timeout(mut self, timeout: Duration) -> Self {
        self.safe_point_timeout = timeout;
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

    /// Returns the arguments declared as 64-bit.
    #[must_use]
    pub fn wide_arguments(&self) -> &[usize] {
        &self.wide_arguments
    }

    /// Returns the selected safe point, if any.
    #[must_use]
    pub fn safe_point(&self) -> Option<Address> {
        self.safe_point
    }

    /// Returns how long the safe-point wait may take.
    #[must_use]
    pub fn safe_point_timeout(&self) -> Duration {
        self.safe_point_timeout
    }
}

impl Default for CallOptions {
    fn default() -> Self {
        Self {
            abi: CallAbi::Auto,
            thread: None,
            wide_arguments: Vec::new(),
            safe_point: None,
            safe_point_timeout: DEFAULT_SAFE_POINT_TIMEOUT,
        }
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
        assert!(options.wide_arguments().is_empty());
        assert_eq!(options.safe_point(), None);
        assert_eq!(options.safe_point_timeout(), DEFAULT_SAFE_POINT_TIMEOUT);
        assert_eq!(CallAbi::default(), CallAbi::Auto);
    }

    #[test]
    fn builder_changes_one_option_at_a_time() {
        let options = CallOptions::new().with_abi(CallAbi::Stdcall).with_thread(7);
        assert_eq!(options.abi(), CallAbi::Stdcall);
        assert_eq!(options.thread(), Some(7));
        assert_eq!(CallOptions::new().with_thread(7).abi(), CallAbi::Auto);
    }

    #[test]
    fn wide_arguments_are_configurable() {
        let options = CallOptions::new().with_wide_arguments(&[1, 3]);
        assert_eq!(options.wide_arguments(), &[1, 3]);
        assert!(CallOptions::new().wide_arguments().is_empty());
    }

    #[test]
    fn safe_point_is_configurable() {
        let options = CallOptions::new()
            .with_safe_point(Address::new(0x401000))
            .with_safe_point_timeout(Duration::from_millis(250));
        assert_eq!(options.safe_point(), Some(Address::new(0x401000)));
        assert_eq!(options.safe_point_timeout(), Duration::from_millis(250));
    }
}
