//! Windows backend: `CreateRemoteThread` plus a generated stub.
//!
//! The stub page is allocated read/write, written through `memdiver`, made
//! read/execute, and executed by a new remote thread. The result/completion
//! block lives in a **separate** writable allocation: `VirtualProtectEx` works
//! on whole pages, so a block next to the stub would become read-only with it.

use std::io;
use std::mem::MaybeUninit;

use memdiver::{Address, Process};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
    VirtualFreeEx, VirtualProtectEx,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, INFINITE, LPTHREAD_START_ROUTINE, OpenProcess,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
};

use crate::error::{CallOutcome, CallStatus, OsFailure, SysError};
use crate::stub::{self, GeneratedStub};
#[cfg(all(test, target_arch = "x86_64"))]
use crate::x86_args::X86Abi;
#[cfg(target_arch = "x86")]
use crate::x86_args::{self, X86Abi, X86Error};
use crate::{Failures, MAX_ARGUMENTS};

/// The calling convention of a Windows call.
///
/// On `x86_64` only [`Abi::Auto`] is valid. On `x86`, [`Abi::Auto`] means
/// `cdecl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Abi {
    /// The platform default: Microsoft `x86_64` or 32-bit `cdecl`.
    Auto,
    /// 32-bit `cdecl`.
    Cdecl,
    /// 32-bit `stdcall`.
    Stdcall,
    /// 32-bit `thiscall` (`this` in `ECX`).
    Thiscall,
    /// 32-bit `fastcall` (first two arguments in `ECX`/`EDX`).
    Fastcall,
}

/// An execution handle that pins the target process.
///
/// The handle requests `PROCESS_CREATE_THREAD`,
/// `PROCESS_QUERY_INFORMATION`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`,
/// `PROCESS_VM_WRITE`, and `PROCESS_SYNCHRONIZE`. It is closed when the value
/// is dropped, or explicitly with [`Execution::close`].
#[derive(Debug)]
pub struct Execution {
    handle: Option<isize>,
}

impl Execution {
    /// Closes the process handle and reports a failure.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Platform`] when `CloseHandle` fails.
    pub fn close(mut self) -> Result<(), SysError> {
        match self.handle.take() {
            Some(handle) => close_handle(handle),
            None => Ok(()),
        }
    }

    /// Returns the raw handle, or zero after it was closed.
    fn raw(&self) -> isize {
        self.handle.unwrap_or(0)
    }
}

impl Drop for Execution {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = close_handle(handle);
        }
    }
}

/// Opens the execution handle for `pid`.
///
/// # Errors
///
/// Returns [`SysError::Open`] with the raw `GetLastError` code when
/// `OpenProcess` fails. The request is never retried with fewer rights.
pub fn open_execution(pid: u32) -> Result<Execution, SysError> {
    let access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_SYNCHRONIZE;
    // SAFETY: `OpenProcess` is called with a valid access mask, no handle
    // inheritance, and the caller-supplied pid. The returned handle is owned
    // by the `Execution` value.
    let handle = unsafe { OpenProcess(access, FALSE, pid) };
    if handle.is_null() {
        return Err(SysError::Open(os_failure("OpenProcess")));
    }
    Ok(Execution {
        handle: Some(handle as isize),
    })
}

/// Calls a function in the target process and returns its integer result.
///
/// The caller must have validated the address, the argument count, and the
/// ABI. The mechanism maps the stub, creates one remote thread, waits for it,
/// reads the result, and frees every allocation it created.
pub fn call(
    execution: &Execution,
    process: &Process,
    function: u64,
    args: &[u64],
    abi: Abi,
    wide_arguments: &[usize],
) -> CallOutcome {
    let mut state = RemoteState::new(execution.raw() as HANDLE, page_size());
    let result = call_inner(&mut state, process, function, args, abi, wide_arguments);
    let cleanup = state.cleanup();
    CallOutcome { result, cleanup }
}

/// Remote allocations and thread owned by one call.
struct RemoteState {
    process: HANDLE,
    page: usize,
    stub: Option<usize>,
    result: Option<usize>,
    thread: Option<isize>,
    thread_created: bool,
    thread_finished: bool,
}

impl RemoteState {
    fn new(process: HANDLE, page: usize) -> Self {
        Self {
            process,
            page,
            stub: None,
            result: None,
            thread: None,
            thread_created: false,
            thread_finished: false,
        }
    }

    /// Allocates `size` bytes at `address`, or anywhere when it is 0.
    fn allocate_at(&self, address: usize, size: usize) -> Result<usize, SysError> {
        // SAFETY: the process handle was opened with PROCESS_VM_OPERATION, the
        // size is page-aligned, and the type/protection combination is valid.
        let pointer = unsafe {
            VirtualAllocEx(
                self.process,
                address as *const core::ffi::c_void,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if pointer.is_null() {
            return Err(SysError::Platform(os_failure("VirtualAllocEx")));
        }
        Ok(pointer as usize)
    }

    /// Allocates one page anywhere in the target.
    fn allocate_any(&self) -> Result<usize, SysError> {
        self.allocate_at(0, self.page)
    }

    /// Tries to place the stub within `rel32` range of the function.
    ///
    /// A direct `call rel32` is not subject to Control Flow Guard and does not
    /// need `ENDBR64` on CET-IBT systems. Placement is best-effort: when no
    /// hint succeeds, the stub is allocated anywhere and the call is encoded
    /// indirectly.
    fn allocate_near(&self, function: u64) -> Result<usize, SysError> {
        const GRANULARITY: u64 = 0x1_0000;
        let base = function & !(GRANULARITY - 1);
        for index in 0..8u64 {
            let step = (index / 2 + 1) * 0x10_0000;
            let hint = if index % 2 == 0 {
                base.saturating_sub(step)
            } else {
                base.saturating_add(step)
            };
            let Ok(hint) = usize::try_from(hint) else {
                continue;
            };
            if hint == 0 {
                continue;
            }
            if let Ok(address) = self.allocate_at(hint, self.page) {
                return Ok(address);
            }
        }
        self.allocate_any()
    }

    /// Changes the stub page to read/execute and flushes the instruction cache.
    fn make_executable(&self, address: usize) -> Result<(), SysError> {
        let mut previous = 0u32;
        // SAFETY: `address` is a committed page owned by the target and the
        // old-protection out pointer is a valid `u32`.
        let changed = unsafe {
            VirtualProtectEx(
                self.process,
                address as *const core::ffi::c_void,
                self.page,
                PAGE_EXECUTE_READ,
                &mut previous,
            )
        };
        if changed == FALSE {
            return Err(SysError::Platform(os_failure("VirtualProtectEx")));
        }
        // SAFETY: the page is now executable and belongs to the target
        // process handle opened for VM operations.
        let flushed = unsafe {
            FlushInstructionCache(self.process, address as *const core::ffi::c_void, self.page)
        };
        if flushed == FALSE {
            return Err(SysError::Platform(os_failure("FlushInstructionCache")));
        }
        Ok(())
    }

    /// Starts one remote thread at `address`.
    fn create_thread(&self, address: usize) -> Result<isize, SysError> {
        // SAFETY: `address` points at the generated stub. Windows enters a
        // thread start routine with the `stdcall` convention and one ignored
        // `lpParameter`; the stub preserves that stack frame and returns with
        // `ret 4`, so the function-pointer type is the correct contract.
        let start: LPTHREAD_START_ROUTINE = Some(unsafe {
            std::mem::transmute::<usize, unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>(
                address,
            )
        });
        // SAFETY: the handle has PROCESS_CREATE_THREAD, no security
        // attributes are required, and the stub is executable in the target.
        let thread = unsafe {
            CreateRemoteThread(
                self.process,
                std::ptr::null(),
                0,
                start,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        if thread.is_null() {
            return Err(SysError::Platform(os_failure("CreateRemoteThread")));
        }
        Ok(thread as isize)
    }

    /// Waits for the remote thread to exit.
    fn wait(&self, thread: isize) -> Result<(), SysError> {
        // SAFETY: `thread` is a valid thread handle and `INFINITE` disables
        // the timeout.
        let result = unsafe { WaitForSingleObject(thread as HANDLE, INFINITE) };
        if result != WAIT_OBJECT_0 {
            return Err(SysError::Platform(os_failure("WaitForSingleObject")));
        }
        Ok(())
    }

    /// Reads the remote thread's exit code.
    fn exit_code(&self, thread: isize) -> Result<u32, SysError> {
        let mut code = 0u32;
        // SAFETY: the thread handle is valid and the out pointer is writable.
        let ok = unsafe { GetExitCodeThread(thread as HANDLE, &mut code) };
        if ok == FALSE {
            return Err(SysError::Platform(os_failure("GetExitCodeThread")));
        }
        Ok(code)
    }

    /// Frees one remote allocation.
    fn free(&self, address: usize) -> Result<(), SysError> {
        // SAFETY: `address` was returned by `VirtualAllocEx` for this process
        // and is released exactly once; `MEM_RELEASE` requires a size of 0.
        let ok = unsafe {
            VirtualFreeEx(
                self.process,
                address as *mut core::ffi::c_void,
                0,
                MEM_RELEASE,
            )
        };
        if ok == FALSE {
            return Err(SysError::Platform(os_failure("VirtualFreeEx")));
        }
        Ok(())
    }

    /// Closes the thread handle and frees both allocations when it is safe.
    ///
    /// When the wait failed, the thread may still be running, so the remote
    /// memory is deliberately leaked and reported. The thread handle is still
    /// closed; closing it does not stop the thread.
    fn cleanup(&mut self) -> Option<SysError> {
        let mut failures = Failures::default();
        let thread_may_run = self.thread.is_some() && !self.thread_finished;

        if let Some(thread) = self.thread.take() {
            failures.record(close_handle(thread));
        }
        if thread_may_run {
            let _ = self.stub.take();
            let _ = self.result.take();
            failures.record_error(Some(SysError::Leak {
                operation: "VirtualFreeEx",
                reason: "the remote thread may still be running",
            }));
            return failures.into_option();
        }
        if let Some(address) = self.result.take() {
            failures.record(self.free(address));
        }
        if let Some(address) = self.stub.take() {
            failures.record(self.free(address));
        }
        failures.into_option()
    }
}

impl Drop for RemoteState {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = close_handle(thread);
        }
        // Panic safety only: the explicit cleanup always runs on the normal
        // path. Never free memory while a thread may still be using it.
        if !self.thread_created || self.thread_finished {
            if let Some(address) = self.result.take() {
                let _ = self.free(address);
            }
            if let Some(address) = self.stub.take() {
                let _ = self.free(address);
            }
        }
    }
}

/// Validates arguments, builds and runs the stub, and reads the result.
fn call_inner(
    state: &mut RemoteState,
    process: &Process,
    function: u64,
    args: &[u64],
    abi: Abi,
    wide_arguments: &[usize],
) -> Result<u64, SysError> {
    if args.len() > MAX_ARGUMENTS {
        return Err(SysError::InvalidArgument {
            index: MAX_ARGUMENTS,
            reason: "at most six arguments are supported",
        });
    }
    #[cfg(target_arch = "x86_64")]
    {
        if abi != Abi::Auto {
            return Err(SysError::Unsupported {
                operation: "remote call",
                reason: "only the platform default ABI is supported on x86_64",
            });
        }
        if !wide_arguments.is_empty() {
            return Err(SysError::Unsupported {
                operation: "remote call",
                reason: "64-bit argument specifications only apply to 32-bit x86 targets",
            });
        }
    }
    #[cfg(target_arch = "x86")]
    let _ = wide_arguments;

    let stub_address = state.allocate_near(function)?;
    state.stub = Some(stub_address);
    let result_address = state.allocate_any()?;
    state.result = Some(result_address);

    let generated = generate(
        stub_address,
        function,
        result_address,
        args,
        abi,
        wide_arguments,
    )?;
    process
        .write(Address::new(stub_address as u64), &generated.bytes)
        .map_err(inspect("Process::write"))?;
    state.make_executable(stub_address)?;

    let thread = state.create_thread(stub_address)?;
    state.thread = Some(thread);
    state.thread_created = true;
    state.wait(thread)?;
    state.thread_finished = true;

    let exit_code = state.exit_code(thread)?;
    if exit_code != 0 {
        return Err(SysError::CallFailed(CallStatus::ThreadExit(exit_code)));
    }
    let (value, completed) = read_result(process, result_address)?;
    if completed == 0 {
        return Err(SysError::CallFailed(CallStatus::NoCompletion));
    }
    Ok(value)
}

/// Builds the stub for the host architecture.
#[cfg(target_arch = "x86_64")]
fn generate(
    stub_address: usize,
    function: u64,
    result: usize,
    args: &[u64],
    _abi: Abi,
    _wide_arguments: &[usize],
) -> Result<GeneratedStub, SysError> {
    Ok(stub::build_x64(
        stub_address as u64,
        function,
        result as u64,
        args,
    ))
}

/// Builds the 32-bit stub for the host architecture.
#[cfg(target_arch = "x86")]
fn generate(
    stub_address: usize,
    function: u64,
    result: usize,
    args: &[u64],
    abi: Abi,
    wide_arguments: &[usize],
) -> Result<GeneratedStub, SysError> {
    let function = u32::try_from(function).map_err(|_| SysError::InvalidAddress {
        address: function,
        reason: "the function address does not fit in a 32-bit target",
    })?;
    let stub_address = u32::try_from(stub_address).map_err(|_| SysError::InvalidAddress {
        address: u64::from(stub_address as u32),
        reason: "the stub address does not fit in a 32-bit target",
    })?;
    let result_address = u32::try_from(result).map_err(|_| SysError::InvalidAddress {
        address: result as u64,
        reason: "the result address does not fit in a 32-bit target",
    })?;

    let layout = x86_args::build(map_abi(abi), args, wide_arguments).map_err(map_x86_error)?;
    Ok(stub::build_x86(
        stub_address,
        function,
        result_address,
        &layout,
    ))
}

/// Maps a 32-bit argument-layout failure to a mechanism error.
#[cfg(target_arch = "x86")]
fn map_x86_error(error: X86Error) -> SysError {
    match error {
        X86Error::Index(index) => SysError::InvalidArgument {
            index,
            reason: "the wide-argument index is out of range",
        },
        X86Error::Duplicate(index) => SysError::InvalidArgument {
            index,
            reason: "the wide-argument index is repeated",
        },
        X86Error::NarrowValue(index) => SysError::InvalidArgument {
            index,
            reason: "the value does not fit in a 32-bit argument slot",
        },
        X86Error::WideRegister => SysError::Unsupported {
            operation: "remote call",
            reason: "64-bit register arguments are not supported; only stack arguments may be wide",
        },
    }
}

/// Maps the public ABI to the 32-bit calling conventions.
#[cfg(any(target_arch = "x86", test))]
fn map_abi(abi: Abi) -> X86Abi {
    match abi {
        Abi::Auto | Abi::Cdecl => X86Abi::Cdecl,
        Abi::Stdcall => X86Abi::Stdcall,
        Abi::Thiscall => X86Abi::Thiscall,
        Abi::Fastcall => X86Abi::Fastcall,
    }
}

/// Reads `{ result: u64, completed: u64 }` from the result allocation.
fn read_result(process: &Process, address: usize) -> Result<(u64, u64), SysError> {
    let mut bytes = [0u8; 16];
    match process.read(Address::new(address as u64), &mut bytes) {
        Ok(()) => {}
        Err(source) => {
            if !process.is_alive() {
                return Err(SysError::CallFailed(CallStatus::Exited));
            }
            return Err(SysError::Inspect {
                operation: "Process::read",
                source: Box::new(source),
            });
        }
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[..8]);
    let mut flag = [0u8; 8];
    flag.copy_from_slice(&bytes[8..]);
    Ok((u64::from_le_bytes(value), u64::from_le_bytes(flag)))
}

/// Returns the target's page size.
fn page_size() -> usize {
    let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
    // SAFETY: `GetSystemInfo` fills the entire `SYSTEM_INFO` value.
    unsafe { GetSystemInfo(info.as_mut_ptr()) };
    // SAFETY: the call above initialized every field.
    let info = unsafe { info.assume_init() };
    usize::try_from(info.dwPageSize).unwrap_or(4096)
}

/// Closes one kernel handle.
fn close_handle(handle: isize) -> Result<(), SysError> {
    // SAFETY: `handle` is owned by the calling type and closed exactly once.
    let ok = unsafe { CloseHandle(handle as HANDLE) };
    if ok == FALSE {
        return Err(SysError::Platform(os_failure("CloseHandle")));
    }
    Ok(())
}

/// Captures the current thread's last Windows error.
fn os_failure(operation: &'static str) -> OsFailure {
    let code = io::Error::last_os_error()
        .raw_os_error()
        .map_or(-1, i64::from);
    OsFailure::new(operation, code)
}

/// Wraps a `memdiver` failure with the operation name.
fn inspect(operation: &'static str) -> impl FnOnce(memdiver::Error) -> SysError {
    move |source| SysError::Inspect {
        operation,
        source: Box::new(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_maps_to_32_bit_conventions() {
        // This mapping is only used on x86; the free function below exists so
        // the translation is unit-testable on any host.
        assert_eq!(map_abi(Abi::Auto), X86Abi::Cdecl);
        assert_eq!(map_abi(Abi::Cdecl), X86Abi::Cdecl);
        assert_eq!(map_abi(Abi::Stdcall), X86Abi::Stdcall);
        assert_eq!(map_abi(Abi::Thiscall), X86Abi::Thiscall);
        assert_eq!(map_abi(Abi::Fastcall), X86Abi::Fastcall);
    }
}
