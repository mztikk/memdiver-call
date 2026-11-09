//! 32-bit Windows call-frame layout.
//!
//! Windows `x86` has no red zone. At function entry the stack must satisfy
//! `ESP % 16 == 12`, the return address is at `[ESP]`, and the arguments are at
//! `[ESP+4]`, `[ESP+8]`, and so on.

/// A validated 32-bit call frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameLayout {
    /// Address of the return address; `frame % 16 == 12`.
    pub(crate) frame: u64,
    /// First byte after the return address and all stack arguments.
    pub(crate) end: u64,
}

/// Computes a call frame below `saved_esp` that holds a return address and
/// `stack_arguments` 32-bit arguments.
pub(crate) fn layout(saved_esp: u64, stack_arguments: usize) -> Option<FrameLayout> {
    let stack_bytes = u64::try_from(stack_arguments).ok()?.checked_mul(4)?;
    // Leave room for the return address and all arguments below the
    // interrupted stack pointer.
    let top = saved_esp.checked_sub(4)?.checked_sub(stack_bytes)?;
    let frame = (top & !0xF).checked_sub(4)?;
    let end = frame.checked_add(4)?.checked_add(stack_bytes)?;
    debug_assert!(
        end <= saved_esp,
        "frame must stay below the interrupted ESP"
    );
    debug_assert_eq!(frame % 16, 12, "the callee needs ESP % 16 == 12 at entry");
    Some(FrameLayout { frame, end })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_places_one_return_address() {
        let layout = layout(0x0036_feb8, 0).expect("frame");
        assert_eq!(layout.frame, 0x0036_feac);
        assert_eq!(layout.frame % 16, 12);
        assert_eq!(layout.end, layout.frame + 4);
        assert!(layout.end <= 0x0036_feb8);
    }

    #[test]
    fn two_arguments_follow_the_return_address() {
        let layout = layout(0x0036_feb8, 2).expect("frame");
        assert_eq!(layout.frame % 16, 12);
        assert_eq!(layout.end, layout.frame + 4 + 8);
        assert!(layout.end <= 0x0036_feb8);
    }

    #[test]
    fn six_arguments_fit() {
        let layout = layout(0x0036_feb8, 6).expect("frame");
        assert_eq!(layout.frame % 16, 12);
        assert_eq!(layout.end, layout.frame + 4 + 24);
        assert!(layout.end <= 0x0036_feb8);
    }

    #[test]
    fn alignment_holds_for_unaligned_saved_esp() {
        for esp in (0x1000..0x2000).step_by(4) {
            let layout = layout(esp, 3).expect("frame");
            assert_eq!(layout.frame % 16, 12, "esp {esp:#x}");
            assert!(layout.end <= esp, "esp {esp:#x}");
        }
    }

    #[test]
    fn low_stack_pointer_is_an_error_not_a_panic() {
        assert_eq!(layout(0, 0), None);
        assert_eq!(layout(4, 0), None);
        assert_eq!(layout(8, 0), None);
        assert_eq!(layout(16, 1), None);
    }
}
