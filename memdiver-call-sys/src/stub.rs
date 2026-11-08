//! Generated remote-call stubs for Windows.
//!
//! The stub is written into a remote readable/writable page, patched with the
//! argument values, the result address, and (optionally) a direct call
//! displacement, then made read/execute. It is deliberately generated as
//! bytes rather than copied from a compiled function: relocating compiled code
//! is not a valid stub strategy.

use crate::MAX_ARGUMENTS;

/// The calling convention of a 32-bit Windows call.
#[cfg(any(target_arch = "x86", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86Abi {
    /// Caller cleans the stack; all arguments are on the stack.
    Cdecl,
    /// Callee cleans the stack; all arguments are on the stack.
    Stdcall,
    /// `this` in `ECX`, remaining arguments on the stack.
    Thiscall,
    /// First two arguments in `ECX`/`EDX`, remaining arguments on the stack.
    Fastcall,
}

/// A generated stub and the encoding chosen for its call instruction.
#[derive(Debug)]
pub(crate) struct GeneratedStub {
    /// Machine code to place at the stub address.
    pub(crate) bytes: Vec<u8>,
    /// Whether the function is reached with a direct `call rel32`.
    #[allow(dead_code)] // read by unit tests
    pub(crate) direct_call: bool,
}

/// Builds the Windows `x86_64` stub.
///
/// Layout, in order:
///
/// ```text
/// sub rsp, 0x38
/// mov rcx, arg0
/// mov rdx, arg1
/// mov r8,  arg2
/// mov r9,  arg3
/// mov rax, arg4 ; mov [rsp+0x20], rax
/// mov rax, arg5 ; mov [rsp+0x28], rax
/// <call the function: E8 rel32 or mov rax, imm64; call rax>
/// mov [result], rax
/// mov rcx, result+8 ; mov qword [rcx], 1
/// xor eax, eax
/// add rsp, 0x38
/// ret
/// ```
///
/// `result` must point to a zeroed 16-byte block in a writable remote
/// allocation that is separate from the stub page.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) fn build_x64(
    stub_address: u64,
    function: u64,
    result: u64,
    args: &[u64],
) -> GeneratedStub {
    debug_assert!(args.len() <= MAX_ARGUMENTS);

    let mut bytes = Vec::with_capacity(128);
    // sub rsp, 0x38 — shadow space, two stack slots, 16-byte alignment.
    bytes.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

    mov_imm64(&mut bytes, 0x48, 0xB9, argument(args, 0)); // rcx
    mov_imm64(&mut bytes, 0x48, 0xBA, argument(args, 1)); // rdx
    mov_imm64(&mut bytes, 0x49, 0xB8, argument(args, 2)); // r8
    mov_imm64(&mut bytes, 0x49, 0xB9, argument(args, 3)); // r9
    mov_imm64(&mut bytes, 0x48, 0xB8, argument(args, 4)); // rax
    bytes.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20], rax
    mov_imm64(&mut bytes, 0x48, 0xB8, argument(args, 5)); // rax
    bytes.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]); // mov [rsp+0x28], rax

    // The call. A direct relocation is not subject to Control Flow Guard and
    // keeps CET-IBT out of the picture; use it whenever the stub is within
    // +/-2 GiB of the function.
    let call_offset = bytes.len();
    let next = stub_address
        .wrapping_add(call_offset as u64)
        .wrapping_add(5);
    let direct = relative_64(next, function);
    match direct {
        Some(rel32) => {
            bytes.push(0xE8);
            bytes.extend_from_slice(&rel32.to_le_bytes());
        }
        None => {
            mov_imm64(&mut bytes, 0x48, 0xB8, function); // mov rax, function
            bytes.extend_from_slice(&[0xFF, 0xD0]); // call rax
        }
    }

    // mov [result], rax — 64-bit absolute store.
    bytes.extend_from_slice(&[0x48, 0xA3]);
    bytes.extend_from_slice(&result.to_le_bytes());
    // Completion flag, written after the result so a reader that observes the
    // flag also observes the result. The block starts zeroed, so a missing
    // flag means the function did not return through the stub.
    mov_imm64(&mut bytes, 0x48, 0xB9, result.wrapping_add(8)); // rcx
    bytes.extend_from_slice(&[0x48, 0xC7, 0x01, 0x01, 0x00, 0x00, 0x00]); // mov [rcx], 1

    // Thread exit code zero.
    bytes.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    bytes.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]); // add rsp, 0x38
    bytes.push(0xC3); // ret

    GeneratedStub {
        bytes,
        direct_call: direct.is_some(),
    }
}

/// Builds the Windows `x86` stub.
///
/// The stub preserves the thread entry frame in `EBP`, aligns `ESP`, writes the
/// stack arguments into a reserved, 16-byte-aligned argument area, loads the
/// register arguments for `thiscall`/`fastcall`, calls the function, stores
/// `EDX:EAX` (the 64-bit integer return), sets the completion flag, and
/// returns with `ret 4` because the thread start routine is `stdcall`.
///
/// `result` must point to a zeroed 16-byte block in a writable remote
/// allocation that is separate from the stub page.
#[cfg(any(target_arch = "x86", test))]
pub(crate) fn build_x86(
    stub_address: u32,
    function: u32,
    result: u32,
    abi: X86Abi,
    args: &[u32],
) -> GeneratedStub {
    debug_assert!(args.len() <= MAX_ARGUMENTS);

    let stack_arguments: &[u32] = match abi {
        X86Abi::Cdecl | X86Abi::Stdcall => args,
        X86Abi::Thiscall => args.get(1..).unwrap_or(&[]),
        X86Abi::Fastcall => args.get(2..).unwrap_or(&[]),
    };

    let mut bytes = Vec::with_capacity(96);
    // push ebp; mov ebp, esp; and esp, -16
    bytes.extend_from_slice(&[0x55, 0x89, 0xE5, 0x83, 0xE4, 0xF0]);

    // Reserve a 16-byte-aligned argument area. `and esp, -16` already
    // aligned ESP, so a multiple-of-16 reservation keeps it aligned.
    let stack_bytes = stack_arguments.len() * 4;
    let reservation = (stack_bytes + 15) & !15;
    if reservation > 0 {
        bytes.extend_from_slice(&[0x83, 0xEC, reservation as u8]); // sub esp, imm8
    }
    for (index, value) in stack_arguments.iter().enumerate() {
        // mov dword ptr [esp + 4*index], imm32
        bytes.extend_from_slice(&[0xC7, 0x44, 0x24, (index * 4) as u8]);
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    match abi {
        X86Abi::Thiscall | X86Abi::Fastcall => {
            bytes.push(0xB9); // mov ecx, imm32
            bytes.extend_from_slice(&argument(args, 0).to_le_bytes());
        }
        X86Abi::Cdecl | X86Abi::Stdcall => {}
    }
    if abi == X86Abi::Fastcall {
        bytes.push(0xBA); // mov edx, imm32
        bytes.extend_from_slice(&argument(args, 1).to_le_bytes());
    }

    let call_offset = bytes.len();
    let next = stub_address.wrapping_add((call_offset as u32).wrapping_add(5));
    let direct = relative_32(next, function);
    match direct {
        Some(rel32) => {
            bytes.push(0xE8);
            bytes.extend_from_slice(&rel32.to_le_bytes());
        }
        None => {
            bytes.push(0xB8); // mov eax, function
            bytes.extend_from_slice(&function.to_le_bytes());
            bytes.extend_from_slice(&[0xFF, 0xD0]); // call eax
        }
    }

    // mov [result], eax ; mov [result+4], edx
    bytes.push(0xA3);
    bytes.extend_from_slice(&result.to_le_bytes());
    bytes.extend_from_slice(&[0x89, 0x15]);
    bytes.extend_from_slice(&result.wrapping_add(4).to_le_bytes());
    // mov dword [result+8], 1
    bytes.extend_from_slice(&[0xC7, 0x05]);
    bytes.extend_from_slice(&result.wrapping_add(8).to_le_bytes());
    bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // xor eax, eax ; mov esp, ebp ; pop ebp ; ret 4
    bytes.extend_from_slice(&[0x31, 0xC0, 0x89, 0xEC, 0x5D, 0xC2, 0x04, 0x00]);

    GeneratedStub {
        bytes,
        direct_call: direct.is_some(),
    }
}

fn argument<T: Copy + Default>(args: &[T], index: usize) -> T {
    args.get(index).copied().unwrap_or_default()
}

#[cfg(any(target_arch = "x86_64", test))]
fn mov_imm64(bytes: &mut Vec<u8>, rex: u8, opcode: u8, value: u64) {
    bytes.push(rex);
    bytes.push(opcode);
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(any(target_arch = "x86_64", test))]
fn relative_64(next: u64, target: u64) -> Option<i32> {
    let delta = i128::from(target) - i128::from(next);
    i32::try_from(delta).ok()
}

#[cfg(any(target_arch = "x86", test))]
fn relative_32(next: u32, target: u32) -> Option<i32> {
    let delta = i128::from(target) - i128::from(next);
    i32::try_from(delta).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x64_stub_is_byte_exact() {
        let stub = build_x64(0x2000_0000, 0x2000_1000, 0x3000_0000, &[1, 2, 3, 4, 5, 6]);
        let expected: &[u8] = &[
            // sub rsp, 0x38
            0x48, 0x83, 0xEC, 0x38, //
            // mov rcx, 1
            0x48, 0xB9, 1, 0, 0, 0, 0, 0, 0, 0, //
            // mov rdx, 2
            0x48, 0xBA, 2, 0, 0, 0, 0, 0, 0, 0, //
            // mov r8, 3
            0x49, 0xB8, 3, 0, 0, 0, 0, 0, 0, 0, //
            // mov r9, 4
            0x49, 0xB9, 4, 0, 0, 0, 0, 0, 0, 0, //
            // mov rax, 5 ; mov [rsp+0x20], rax
            0x48, 0xB8, 5, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x20, //
            // mov rax, 6 ; mov [rsp+0x28], rax
            0x48, 0xB8, 6, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x28, //
            // call rel32: 0x2000_1000 - 0x2000_004F = 0xFB1
            0xE8, 0xB1, 0x0F, 0x00, 0x00, //
            // mov [0x3000_0000], rax
            0x48, 0xA3, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, //
            // mov rcx, 0x3000_0008 ; mov qword [rcx], 1
            0x48, 0xB9, 0x08, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x01, 0x01,
            0x00, 0x00, 0x00, //
            // xor eax, eax ; add rsp, 0x38 ; ret
            0x31, 0xC0, 0x48, 0x83, 0xC4, 0x38, 0xC3,
        ];
        assert_eq!(stub.bytes, expected);
        assert!(stub.direct_call);
        assert_eq!(stub.bytes.len(), 113);
    }

    #[test]
    fn x64_uses_an_indirect_call_when_out_of_range() {
        let stub = build_x64(0x2000_0000, 0x7FFF_0000_0000, 0x3000_0000, &[]);
        assert!(!stub.direct_call);
        let call_offset = 74;
        assert_eq!(&stub.bytes[call_offset..call_offset + 2], &[0x48, 0xB8]);
        assert_eq!(
            &stub.bytes[call_offset + 2..call_offset + 10],
            &0x7FFF_0000_0000u64.to_le_bytes()
        );
        assert_eq!(
            &stub.bytes[call_offset + 10..call_offset + 12],
            &[0xFF, 0xD0]
        );
    }

    #[test]
    fn x64_missing_arguments_are_zero() {
        let stub = build_x64(0x2000_0000, 0x2000_1000, 0x3000_0000, &[7]);
        // rdx is argument 2 and must be zero.
        assert_eq!(&stub.bytes[14..24], &[0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0]);
        // r9 is argument 4 and must be zero.
        assert_eq!(&stub.bytes[34..44], &[0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn x64_result_addresses_are_patched() {
        let stub = build_x64(0x2000_0000, 0x2000_1000, 0xDEAD_B000, &[]);
        let bytes = &stub.bytes;
        let result_store = 4 + 40 + 30 + 5;
        assert_eq!(&bytes[result_store..result_store + 2], &[0x48, 0xA3]);
        assert_eq!(
            &bytes[result_store + 2..result_store + 10],
            &0xDEAD_B000u64.to_le_bytes()
        );
        let completion = result_store + 10;
        assert_eq!(&bytes[completion..completion + 2], &[0x48, 0xB9]);
        assert_eq!(
            &bytes[completion + 2..completion + 10],
            &0xDEAD_B008u64.to_le_bytes()
        );
    }

    #[test]
    fn x86_cdecl_six_arguments_is_byte_exact() {
        let stub = build_x86(
            0x0040_0000,
            0x0040_1000,
            0x0050_0000,
            X86Abi::Cdecl,
            &[1, 2, 3, 4, 5, 6],
        );
        let expected: &[u8] = &[
            // push ebp; mov ebp, esp; and esp, -16; sub esp, 32
            0x55, 0x89, 0xE5, 0x83, 0xE4, 0xF0, 0x83, 0xEC, 0x20, //
            // six stack dwords at [esp+0..20]
            0xC7, 0x44, 0x24, 0x00, 1, 0, 0, 0, //
            0xC7, 0x44, 0x24, 0x04, 2, 0, 0, 0, //
            0xC7, 0x44, 0x24, 0x08, 3, 0, 0, 0, //
            0xC7, 0x44, 0x24, 0x0C, 4, 0, 0, 0, //
            0xC7, 0x44, 0x24, 0x10, 5, 0, 0, 0, //
            0xC7, 0x44, 0x24, 0x14, 6, 0, 0, 0, //
            // call rel32: 0x401000 - 0x40003E = 0xFC2
            0xE8, 0xC2, 0x0F, 0x00, 0x00, //
            // mov [0x0050_0000], eax ; mov [0x0050_0004], edx
            0xA3, 0x00, 0x00, 0x50, 0x00, //
            0x89, 0x15, 0x04, 0x00, 0x50, 0x00, //
            // mov dword [0x0050_0008], 1
            0xC7, 0x05, 0x08, 0x00, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, //
            // xor eax, eax ; mov esp, ebp ; pop ebp ; ret 4
            0x31, 0xC0, 0x89, 0xEC, 0x5D, 0xC2, 0x04, 0x00,
        ];
        assert_eq!(stub.bytes, expected);
        assert!(stub.direct_call);
        assert_eq!(stub.bytes.len(), 91);
    }

    #[test]
    fn x86_thiscall_puts_this_in_ecx() {
        let stub = build_x86(
            0x0040_0000,
            0x0040_1000,
            0x0050_0000,
            X86Abi::Thiscall,
            &[0xAA, 1, 2],
        );
        let bytes = &stub.bytes;
        // Two stack arguments (1, 2), reservation of 16.
        assert_eq!(&bytes[6..9], &[0x83, 0xEC, 0x10]);
        assert_eq!(&bytes[9..17], &[0xC7, 0x44, 0x24, 0x00, 1, 0, 0, 0]);
        assert_eq!(&bytes[17..25], &[0xC7, 0x44, 0x24, 0x04, 2, 0, 0, 0]);
        // mov ecx, 0xAA
        assert_eq!(&bytes[25..30], &[0xB9, 0xAA, 0, 0, 0]);
        // Only the two stack arguments: `this` is not stored on the stack.
        assert!(bytes[9..25].iter().all(|&byte| byte != 0xAA));
    }

    #[test]
    fn x86_fastcall_puts_two_arguments_in_registers() {
        let stub = build_x86(
            0x0040_0000,
            0x0040_1000,
            0x0050_0000,
            X86Abi::Fastcall,
            &[0x11, 0x22, 0x33],
        );
        let bytes = &stub.bytes;
        assert_eq!(&bytes[6..9], &[0x83, 0xEC, 0x10]);
        // Only argument 3 is on the stack.
        assert_eq!(&bytes[9..17], &[0xC7, 0x44, 0x24, 0x00, 0x33, 0, 0, 0]);
        // mov ecx, 0x11 ; mov edx, 0x22
        assert_eq!(&bytes[17..22], &[0xB9, 0x11, 0, 0, 0]);
        assert_eq!(&bytes[22..27], &[0xBA, 0x22, 0, 0, 0]);
    }

    #[test]
    fn x86_stdcall_uses_the_stack_like_cdecl() {
        let stub = build_x86(
            0x0040_0000,
            0x0040_1000,
            0x0050_0000,
            X86Abi::Stdcall,
            &[7, 8],
        );
        let bytes = &stub.bytes;
        assert_eq!(&bytes[6..9], &[0x83, 0xEC, 0x10]);
        assert_eq!(&bytes[9..17], &[0xC7, 0x44, 0x24, 0x00, 7, 0, 0, 0]);
        assert_eq!(&bytes[17..25], &[0xC7, 0x44, 0x24, 0x04, 8, 0, 0, 0]);
        // The stub restores ESP itself, so callee stack cleanup is harmless.
        assert_eq!(&bytes[bytes.len() - 2..], &[0x04, 0x00]);
    }

    #[test]
    fn x86_no_stack_arguments_skips_reservation() {
        let stub = build_x86(0x0040_0000, 0x0040_1000, 0x0050_0000, X86Abi::Cdecl, &[]);
        assert_eq!(
            &stub.bytes[..9],
            &[0x55, 0x89, 0xE5, 0x83, 0xE4, 0xF0, 0xE8, 0xF5, 0x0F]
        );
    }

    #[test]
    fn x86_uses_an_indirect_call_when_out_of_range() {
        let stub = build_x86(0x0040_0000, 0xF000_0000, 0x0050_0000, X86Abi::Cdecl, &[1]);
        assert!(!stub.direct_call);
        // 6-byte prefix, 3-byte reservation, 8-byte argument store.
        let call = &stub.bytes[17..];
        assert_eq!(&call[..7], &[0xB8, 0x00, 0x00, 0x00, 0xF0, 0xFF, 0xD0]);
    }
}
