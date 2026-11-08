//! x86 debug-register selection and encoding.
//!
//! Only the four execution breakpoints in `DR0`–`DR3` are used. `DR4`/`DR5`
//! are aliases on CPUs without debug extensions and are never written.

/// Number of available hardware breakpoint slots.
pub(crate) const SLOT_COUNT: u8 = 4;

/// Returns the index of the first free execution-breakpoint slot.
///
/// A slot is free when both its local-enable bit (`Ln`) and its
/// global-enable bit (`Gn`) are clear in `DR7`.
pub(crate) fn free_slot(dr7: u64) -> Option<u8> {
    (0..SLOT_COUNT).find(|&slot| (dr7 >> (2 * u64::from(slot))) & 0b11 == 0)
}

/// Returns `DR7` with `slot` configured as a local execution breakpoint.
///
/// The slot's `RW`/`LEN` fields are cleared (`RW = 00`, `LEN = 00`: execute,
/// one byte) and its local-enable bit is set. Every other bit, including the
/// global-enable bit of the slot (which must already be clear) and the
/// configuration of the other slots, is preserved.
pub(crate) fn enable_execute(dr7: u64, slot: u8) -> u64 {
    debug_assert!(slot < SLOT_COUNT);
    let rw_len_shift = 16 + 4 * u64::from(slot);
    let cleared = dr7 & !(0b1111u64 << rw_len_shift);
    cleared | (1 << (2 * u64::from(slot)))
}

/// Returns `true` when `DR6` reports a hit for `slot`.
pub(crate) fn is_hit(dr6: u64, slot: u8) -> bool {
    slot < SLOT_COUNT && dr6 & (1 << u64::from(slot)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_first_free_slot() {
        assert_eq!(free_slot(0), Some(0));
        assert_eq!(free_slot(0b11), Some(1));
        assert_eq!(free_slot(0b1111), Some(2));
        assert_eq!(free_slot(0b11_1111), Some(3));
        assert_eq!(free_slot(0b1111_1111), None);
    }

    #[test]
    fn a_global_enable_also_occupies_the_slot() {
        // G0 is bit 1.
        assert_eq!(free_slot(0b10), Some(1));
        assert_eq!(free_slot(0b1), Some(1));
    }

    #[test]
    fn enabling_a_slot_sets_only_its_local_enable_bit() {
        assert_eq!(enable_execute(0, 0), 0b1);
        assert_eq!(enable_execute(0, 1), 0b100);
        assert_eq!(enable_execute(0, 3), 0b0100_0000);
    }

    #[test]
    fn enabling_clears_the_slots_rw_len_fields() {
        // Slot 0 configured as a 4-byte data breakpoint: RW=01, LEN=11.
        let dr7 = (0b11 << 18) | (0b01 << 16) | 0b1;
        assert_eq!(enable_execute(dr7, 0), 0b1);
        // Slot 1 with garbage in its field and slot 0 occupied.
        let dr7 = (0b1010 << 20) | 0b1;
        assert_eq!(enable_execute(dr7, 1), 0b100 | 0b1);
    }

    #[test]
    fn enabling_preserves_unrelated_bits() {
        // LE (bit 8), GE (bit 9), GD (bit 13), and a configured slot 2.
        let dr7 = (1 << 8) | (1 << 9) | (1 << 13) | (0b10 << 24) | (0b11 << 26);
        let updated = enable_execute(dr7, 0);
        let control = (1 << 8) | (1 << 9) | (1 << 13);
        assert_eq!(updated & control, dr7 & control);
        // Slot 2 is untouched because slot 0 is the slot being enabled.
        assert_eq!(updated & (0b1111 << 24), dr7 & (0b1111 << 24));
        // Slot 0's RW/LEN field is cleared and its local-enable bit is set.
        assert_eq!(updated & (0b1111 << 16), 0);
        assert_eq!(updated & 0b1, 0b1);
    }

    #[test]
    fn hit_detection_checks_the_slot_bit() {
        assert!(is_hit(0b1, 0));
        assert!(!is_hit(0b1, 1));
        assert!(is_hit(0b1000, 3));
        assert!(!is_hit(0, 0));
        assert!(!is_hit(u64::MAX, 4));
    }
}
