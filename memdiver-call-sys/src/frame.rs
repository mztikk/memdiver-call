//! Red-zone-safe call-frame layout for the SysV AMD64 ABI.

use crate::MAX_ARGUMENTS;

/// Size of the SysV AMD64 red zone, in bytes.
///
/// A leaf function may use the 128 bytes below `RSP`; a call frame must never
/// be placed there.
pub(crate) const RED_ZONE: u64 = 128;

/// Bytes of writable stack that must remain below the call frame.
///
/// This is a guard band, not a proof that the callee's stack usage fits.
#[cfg(target_os = "linux")]
pub(crate) const STACK_HEADROOM: u64 = 4096;

/// A call frame placed inside the interrupted thread's stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameLayout {
    /// Address of the return address. Must be `8 mod 16` so the callee sees
    /// the ABI-required `RSP % 16 == 8` at entry.
    pub(crate) frame: u64,
    /// First byte after the return address and all stack arguments.
    pub(crate) end: u64,
}

/// Computes the highest safe call frame below `saved_rsp`.
///
/// Returns `None` when the arithmetic leaves the address space or when the
/// resulting frame would overlap the red zone. The frame is placed below the
/// red zone, with arguments 7 and later directly above the return address.
pub(crate) fn layout(saved_rsp: u64, argument_count: usize) -> Option<FrameLayout> {
    let stack_arguments = u64::try_from(argument_count.saturating_sub(MAX_ARGUMENTS)).ok()?;
    let stack_bytes = stack_arguments.checked_mul(8)?;

    // Everything below `limit` belongs to the frame; `limit` itself is two
    // words below the red zone so the 16-byte-down rounding has room.
    let limit = saved_rsp.checked_sub(RED_ZONE)?.checked_sub(stack_bytes)?;
    let aligned = limit.checked_sub(8)? & !0xF;
    let frame = aligned.checked_sub(8)?;
    let end = frame.checked_add(8)?.checked_add(stack_bytes)?;

    // The frame must end at or below the red zone.
    if end > saved_rsp.checked_sub(RED_ZONE)? {
        return None;
    }
    if frame % 16 != 8 {
        return None;
    }
    Some(FrameLayout { frame, end })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_arguments_use_only_register_slots() {
        let layout = layout(0x1000_0000, 6).expect("frame");
        assert_eq!(layout.frame % 16, 8);
        assert_eq!(layout.end, layout.frame + 8);
        assert!(layout.end <= 0x1000_0000 - RED_ZONE);
        assert_eq!(layout.frame, 0x0FFF_FF68);
    }

    #[test]
    fn zero_arguments_place_one_return_address() {
        let layout = layout(0x1000_0000, 0).expect("frame");
        assert_eq!(layout.frame % 16, 8);
        assert_eq!(layout.end, layout.frame + 8);
        assert!(layout.end <= 0x1000_0000 - RED_ZONE);
    }

    #[test]
    fn stack_arguments_start_above_the_return_address() {
        let layout = layout(0x1000_0000, 8).expect("frame");
        assert_eq!(layout.frame % 16, 8);
        assert_eq!(layout.end, layout.frame + 8 + 16);
        assert!(layout.end <= 0x1000_0000 - RED_ZONE);
        // Two stack slots fit between the return address and the red zone.
        assert!(layout.frame + 8 + 16 <= 0x1000_0000 - RED_ZONE);
    }

    #[test]
    fn eleven_arguments_still_fit() {
        let layout = layout(0x1000_0000, 11).expect("frame");
        assert_eq!(layout.end, layout.frame + 8 + 40);
        assert!(layout.end <= 0x1000_0000 - RED_ZONE);
    }

    #[test]
    fn low_stack_pointer_is_an_error_not_a_panic() {
        assert_eq!(layout(0, 0), None);
        assert_eq!(layout(64, 0), None);
        assert_eq!(layout(128, 0), None);
        assert_eq!(layout(136, 0), None);
    }

    #[test]
    fn alignment_holds_for_unaligned_saved_rsp() {
        for rsp in (0x1000..0x2000).step_by(8) {
            let layout = layout(rsp, 7).expect("frame");
            assert_eq!(layout.frame % 16, 8, "rsp {rsp:#x}");
            assert!(layout.end <= rsp - RED_ZONE, "rsp {rsp:#x}");
            assert!(layout.frame < rsp);
        }
    }

    #[test]
    fn high_addresses_do_not_overflow() {
        // A stack pointer near the top of the address space is representable;
        // region validation, not this arithmetic, rejects it as unmapped.
        assert!(layout(u64::MAX, 0).is_some());
        assert!(layout(u64::MAX - 64, 0).is_some());
        assert!(layout(u64::MAX - 1000, 9).is_some());
    }
}
