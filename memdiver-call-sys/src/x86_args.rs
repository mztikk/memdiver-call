//! 32-bit Windows argument layout, including 64-bit stack arguments.
//!
//! The x86 Microsoft ABI passes 64-bit integer arguments as two 32-bit stack
//! slots, low-order first. Microsoft documents that the x86 compiler does not
//! automatically 8-byte-align types larger than four bytes on the stack, so the
//! slots follow each other without padding. Register arguments (`this` in
//! `ECX`, or the first two `fastcall` arguments) are 32-bit; a wide register
//! argument is rejected.

/// The calling convention of a 32-bit Windows function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86Abi {
    /// All arguments on the stack; the caller cleans up.
    Cdecl,
    /// All arguments on the stack; the callee cleans up.
    Stdcall,
    /// `this` in `ECX`; the remaining arguments on the stack.
    Thiscall,
    /// First two arguments in `ECX`/`EDX`; the remainder on the stack.
    Fastcall,
}

/// One 32- or 64-bit argument value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86Argument {
    /// Numeric value, truncated for 32-bit arguments.
    pub(crate) value: u64,
    /// Whether the argument occupies two 32-bit stack slots.
    pub(crate) wide: bool,
}

/// The resolved register and stack placement of a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct X86Layout {
    /// Value for `ECX`, if the convention uses it.
    pub(crate) ecx: Option<u32>,
    /// Value for `EDX`, if the convention uses it.
    pub(crate) edx: Option<u32>,
    /// Dwords written at `[ESP]`, `[ESP+4]`, ... before the `call`; the callee
    /// sees them at `[ESP+4]` and later.
    pub(crate) stack: Vec<u32>,
}

/// Why a 32-bit argument list cannot be laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86Error {
    /// A wide-argument index is not a valid argument index.
    Index(usize),
    /// A wide-argument index appears twice.
    Duplicate(usize),
    /// A register argument (`this` or a `fastcall` argument) is 64-bit.
    WideRegister,
    /// A non-wide argument does not fit in 32 bits.
    NarrowValue(usize),
}

/// Builds the register and stack placement for `abi`.
pub(crate) fn build(abi: X86Abi, values: &[u64], wide: &[usize]) -> Result<X86Layout, X86Error> {
    let mut is_wide = vec![false; values.len()];
    for &index in wide {
        let slot = is_wide.get_mut(index).ok_or(X86Error::Index(index))?;
        if *slot {
            return Err(X86Error::Duplicate(index));
        }
        *slot = true;
    }
    let arguments: Vec<X86Argument> = values
        .iter()
        .zip(is_wide)
        .map(|(value, wide)| X86Argument {
            value: *value,
            wide,
        })
        .collect();

    let mut layout = X86Layout {
        ecx: None,
        edx: None,
        stack: Vec::with_capacity(values.len() * 2),
    };
    let stack_start = match abi {
        X86Abi::Cdecl | X86Abi::Stdcall => 0,
        X86Abi::Thiscall => {
            if let Some(this) = arguments.first() {
                layout.ecx = Some(narrow(this, 0)?);
            }
            1
        }
        X86Abi::Fastcall => {
            if let Some(first) = arguments.first() {
                layout.ecx = Some(narrow(first, 0)?);
            }
            if let Some(second) = arguments.get(1) {
                layout.edx = Some(narrow(second, 1)?);
            }
            2
        }
    };
    for (index, argument) in arguments.iter().enumerate().skip(stack_start) {
        if argument.wide {
            layout.stack.push(argument.value as u32);
            layout.stack.push((argument.value >> 32) as u32);
        } else {
            layout.stack.push(narrow(argument, index)?);
        }
    }
    Ok(layout)
}

/// Returns a 32-bit value or reports that it does not fit.
fn narrow(argument: &X86Argument, index: usize) -> Result<u32, X86Error> {
    if argument.wide || argument.value > u64::from(u32::MAX) {
        return Err(if argument.wide {
            X86Error::WideRegister
        } else {
            X86Error::NarrowValue(index)
        });
    }
    Ok(argument.value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdecl_places_narrow_arguments_in_order() {
        let layout = build(X86Abi::Cdecl, &[1, 2, 3], &[]).expect("layout");
        assert_eq!(layout.ecx, None);
        assert_eq!(layout.edx, None);
        assert_eq!(layout.stack, vec![1, 2, 3]);
    }

    #[test]
    fn cdecl_places_wide_arguments_low_then_high() {
        let layout = build(X86Abi::Cdecl, &[0x1122_3344_5566_7788, 0x99], &[0]).expect("layout");
        assert_eq!(layout.stack, vec![0x5566_7788, 0x1122_3344, 0x99]);
    }

    #[test]
    fn thiscall_takes_this_from_ecx() {
        let layout = build(X86Abi::Thiscall, &[0xAA, 1, 2], &[]).expect("layout");
        assert_eq!(layout.ecx, Some(0xAA));
        assert_eq!(layout.edx, None);
        assert_eq!(layout.stack, vec![1, 2]);
    }

    #[test]
    fn thiscall_wide_fields_follow_this() {
        // CSimpleTop::SendMovementUpdate-like: this, uint64 transport, uint8 seat.
        let layout =
            build(X86Abi::Thiscall, &[0x1000, 0x0000_0002_0000_0003, 7], &[1]).expect("layout");
        assert_eq!(layout.ecx, Some(0x1000));
        assert_eq!(layout.stack, vec![3, 2, 7]);
    }

    #[test]
    fn fastcall_uses_both_register_arguments() {
        let layout = build(X86Abi::Fastcall, &[0x11, 0x22, 3, 4], &[]).expect("layout");
        assert_eq!(layout.ecx, Some(0x11));
        assert_eq!(layout.edx, Some(0x22));
        assert_eq!(layout.stack, vec![3, 4]);
    }

    #[test]
    fn wide_register_arguments_are_rejected() {
        assert_eq!(
            build(X86Abi::Thiscall, &[1, 2], &[0]),
            Err(X86Error::WideRegister)
        );
        assert_eq!(
            build(X86Abi::Fastcall, &[1, 2], &[1]),
            Err(X86Error::WideRegister)
        );
    }

    #[test]
    fn narrow_values_must_fit() {
        assert_eq!(
            build(X86Abi::Cdecl, &[u64::from(u32::MAX) + 1], &[]),
            Err(X86Error::NarrowValue(0))
        );
        assert_eq!(
            build(X86Abi::Cdecl, &[0x1_0000_0005], &[0]).map(|l| l.stack),
            Ok(vec![5, 1])
        );
    }

    #[test]
    fn wide_indices_are_validated() {
        assert_eq!(build(X86Abi::Cdecl, &[1], &[1]), Err(X86Error::Index(1)));
        assert_eq!(
            build(X86Abi::Cdecl, &[1, 2], &[0, 0]),
            Err(X86Error::Duplicate(0))
        );
    }
}
