use {
    crate::{MAX_ACCOUNTS_PER_TRANSACTION, MAX_INSTRUCTION_TRACE_LENGTH},
    solana_sbpf::ebpf::MM_RODATA_START,
};

#[derive(Copy, Clone)]
pub struct GuestMemorySection {
    base_guest_address: u64,
    base_region_index: usize,
    maximum_regions: usize,
}

impl GuestMemorySection {
    pub const fn new_following(
        previous_section: GuestMemorySection,
        maximum_regions: usize,
    ) -> Self {
        Self {
            base_guest_address: previous_section.guest_address_range().end,
            base_region_index: previous_section
                .base_region_index
                .checked_add(previous_section.maximum_regions)
                .unwrap(),
            maximum_regions,
        }
    }

    pub const fn new_after_gap(
        previous_section: GuestMemorySection,
        gap_regions: usize,
        maximum_regions: usize,
    ) -> Self {
        let gap = (gap_regions as u64).checked_mul(GUEST_REGION_SIZE).unwrap();
        Self {
            base_guest_address: previous_section
                .guest_address_range()
                .end
                .checked_add(gap)
                .unwrap(),
            base_region_index: previous_section
                .base_region_index
                .checked_add(previous_section.maximum_regions)
                .unwrap(),
            maximum_regions,
        }
    }

    pub const fn region_index_range(self) -> std::ops::Range<usize> {
        std::ops::Range {
            start: self.base_region_index,
            end: self
                .base_region_index
                .checked_add(self.maximum_regions)
                .unwrap(),
        }
    }

    pub const fn region_index(self) -> usize {
        assert!(self.maximum_regions == 1);
        self.base_region_index
    }

    pub const fn region_index_containing(self, addr: u64) -> Option<usize> {
        let Some(section_offset) = addr.checked_sub(self.base_guest_address) else {
            return None;
        };
        let region_index = (section_offset >> SHIFT) as usize;
        if region_index < self.maximum_regions {
            Some(region_index)
        } else {
            None
        }
    }

    pub const fn guest_address_range(self) -> std::ops::Range<u64> {
        let end = (self.maximum_regions as u64)
            .checked_mul(GUEST_REGION_SIZE)
            .unwrap()
            .checked_add(self.base_guest_address)
            .unwrap();
        std::ops::Range {
            start: self.base_guest_address,
            end,
        }
    }

    pub const fn guest_address_range_for(self, region: usize) -> std::ops::Range<u64> {
        if region >= self.maximum_regions {
            panic!("section has insufficient regions for the request");
        }
        let start = (region as u64)
            .checked_mul(GUEST_REGION_SIZE)
            .unwrap()
            .checked_add(self.base_guest_address)
            .unwrap();
        std::ops::Range {
            start,
            end: start.checked_add(GUEST_REGION_SIZE).unwrap(),
        }
    }

    pub fn contains_guest_ptr(&self, addr: u64) -> bool {
        self.guest_address_range().contains(&addr)
    }
}

pub const SHIFT: u32 = 32;
pub const GUEST_REGION_SIZE: u64 = 1 << SHIFT;

pub const RODATA_SECTION: GuestMemorySection = GuestMemorySection {
    base_guest_address: MM_RODATA_START,
    base_region_index: 0,
    maximum_regions: 1,
};
pub const BYTECODE_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(RODATA_SECTION, 1);
pub const STACK_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(BYTECODE_SECTION, 1);
pub const HEAP_SECTION: GuestMemorySection = GuestMemorySection::new_following(STACK_SECTION, 1);
pub const TX_FRAME_SECTION: GuestMemorySection = GuestMemorySection::new_following(HEAP_SECTION, 1);
pub const ACCOUNT_METADATA_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(TX_FRAME_SECTION, 1);
pub const INSTRUCTION_TRACE_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(ACCOUNT_METADATA_SECTION, 1);
pub const RETURN_DATA_SCRATCHPAD_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(INSTRUCTION_TRACE_SECTION, 1);
pub const ACCOUNT_PAYLOAD_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(RETURN_DATA_SCRATCHPAD_SECTION, MAX_ACCOUNTS_PER_TRANSACTION);

// Sysvar regions are inside the "account payload" section with a capacity for `u16::MAX`
// "regions", and extend from the end of that section towards the beginning of it.
pub const NUM_SYSVAR_REGIONS: usize = 7;
pub const SYSVAR_ACCOUNT_SECTION: GuestMemorySection = GuestMemorySection::new_after_gap(
    ACCOUNT_PAYLOAD_SECTION,
    u16::MAX as usize - MAX_ACCOUNTS_PER_TRANSACTION - NUM_SYSVAR_REGIONS,
    NUM_SYSVAR_REGIONS,
);

pub const INSTRUCTION_DATA_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(SYSVAR_ACCOUNT_SECTION, MAX_INSTRUCTION_TRACE_LENGTH);
pub const INSTRUCTION_ACCOUNTS_SECTION: GuestMemorySection =
    GuestMemorySection::new_following(INSTRUCTION_DATA_SECTION, MAX_INSTRUCTION_TRACE_LENGTH);

pub const ALL_SECTIONS: [GuestMemorySection; 12] = [
    RODATA_SECTION,
    BYTECODE_SECTION,
    HEAP_SECTION,
    STACK_SECTION,
    TX_FRAME_SECTION,
    ACCOUNT_METADATA_SECTION,
    INSTRUCTION_TRACE_SECTION,
    RETURN_DATA_SCRATCHPAD_SECTION,
    ACCOUNT_PAYLOAD_SECTION,
    SYSVAR_ACCOUNT_SECTION,
    INSTRUCTION_DATA_SECTION,
    INSTRUCTION_ACCOUNTS_SECTION,
];

#[expect(clippy::indexing_slicing)] // not applicable to `const {}`.
pub const NUM_REGIONS: usize = const {
    let (mut sum, mut i) = (0, 0);
    while i < ALL_SECTIONS.len() {
        sum += ALL_SECTIONS[i].maximum_regions;
        i += 1;
    }
    sum
};
