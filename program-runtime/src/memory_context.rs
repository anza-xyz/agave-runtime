use {
    crate::invoke_context::BpfAllocator,
    solana_instruction::error::InstructionError,
    solana_sbpf::{
        elf::Executable,
        memory_region::{AccessViolationHandler, MemoryMapping, MemoryRegion},
        program::SBPFVersion,
        vm::{Config, ContextObject},
    },
    solana_transaction_context::{
        IndexOfAccount,
        transaction::TransactionContext,
        vm_addresses::{
            self, ACCOUNT_METADATA_SECTION, ACCOUNT_PAYLOAD_SECTION, BYTECODE_SECTION,
            HEAP_SECTION, INSTRUCTION_ACCOUNTS_SECTION, INSTRUCTION_DATA_SECTION,
            INSTRUCTION_TRACE_SECTION, RETURN_DATA_SCRATCHPAD_SECTION, RODATA_SECTION,
            STACK_SECTION, SYSVAR_ACCOUNT_SECTION, TX_FRAME_SECTION,
        },
    },
};

enum MemoryContextType {
    ABIv1(MemoryContext),
    Placeholder,
    ABIv2,
}

pub struct MemoryContexts {
    contexts: Vec<MemoryContextType>,
    abiv2_mappings: Box<MemoryMapping>,
}

impl MemoryContexts {
    pub(crate) fn new() -> Self {
        Self {
            contexts: Vec::new(),
            abiv2_mappings: Box::new(unsafe {
                MemoryMapping::new(Vec::new(), &Config::default(), SBPFVersion::Reserved).unwrap()
            }),
        }
    }

    /// Set this instruction's [`MemoryContext`].
    pub fn set_memory_context_abi_v1(
        &mut self,
        memory_context: MemoryContext,
    ) -> Result<(), InstructionError> {
        *self
            .contexts
            .last_mut()
            .ok_or(InstructionError::CallDepth)? = MemoryContextType::ABIv1(memory_context);
        Ok(())
    }

    /// Get current instruction's [`MemoryContext`]
    pub fn memory_context_abi_v1(&self) -> Result<&MemoryContext, InstructionError> {
        match self.contexts.last().ok_or(InstructionError::CallDepth)? {
            MemoryContextType::ABIv1(ctx) => Ok(ctx),
            MemoryContextType::Placeholder => Err(InstructionError::ProgramEnvironmentSetupFailure),
            MemoryContextType::ABIv2 => Err(InstructionError::InvalidAccountData),
        }
    }

    /// Get current instruction's [`MemoryContext`] for mutable use.
    pub fn memory_context_mut_abi_v1(&mut self) -> Result<&mut MemoryContext, InstructionError> {
        let context = self
            .contexts
            .last_mut()
            .ok_or(InstructionError::CallDepth)?;

        match context {
            MemoryContextType::ABIv1(ctx) => Ok(ctx),
            MemoryContextType::Placeholder => Err(InstructionError::ProgramEnvironmentSetupFailure),
            MemoryContextType::ABIv2 => Err(InstructionError::ProgramEnvironmentSetupFailure),
        }
    }

    pub fn memory_mapping(&self) -> Result<&MemoryMapping, InstructionError> {
        let mapping = match self.contexts.last().ok_or(InstructionError::CallDepth)? {
            MemoryContextType::ABIv1(ctx) => &ctx.memory_mapping,
            MemoryContextType::Placeholder => {
                return Err(InstructionError::ProgramEnvironmentSetupFailure);
            }
            MemoryContextType::ABIv2 => &self.abiv2_mappings,
        };

        Ok(mapping)
    }

    pub fn memory_mapping_mut(&mut self) -> Result<&mut MemoryMapping, InstructionError> {
        let mapping = match self
            .contexts
            .last_mut()
            .ok_or(InstructionError::CallDepth)?
        {
            MemoryContextType::ABIv1(ctx) => &mut ctx.memory_mapping,
            MemoryContextType::Placeholder => {
                return Err(InstructionError::ProgramEnvironmentSetupFailure);
            }
            MemoryContextType::ABIv2 => &mut self.abiv2_mappings,
        };

        Ok(mapping)
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub fn mock_set_mapping_abi_v1(&mut self, memory_mapping: MemoryMapping) {
        self.contexts = vec![MemoryContextType::ABIv1(MemoryContext {
            allocator: BpfAllocator::new(0),
            accounts_metadata: vec![],
            memory_mapping: Box::new(memory_mapping),
        })];
    }

    #[cfg(feature = "dev-context-only-utils")]
    pub fn mock_set_mapping_abi_v2(&mut self, memory_mapping: MemoryMapping) {
        *self.abiv2_mappings = memory_mapping;
        self.contexts = vec![MemoryContextType::ABIv2];
    }

    pub fn push_placeholder(&mut self) {
        // We are only pushing a placeholder to be configured later
        self.contexts.push(MemoryContextType::Placeholder);
    }

    pub fn pop(&mut self) {
        self.contexts.pop();
    }

    pub fn abi_v2_regions_exist(&self) -> bool {
        !self.abiv2_mappings.get_regions().is_empty()
    }

    pub fn create_abi_v2_mappings<C: ContextObject>(
        &mut self,
        regions: Vec<MemoryRegion>,
        executable: &Executable<C>,
        access_violation_handler: AccessViolationHandler,
    ) {
        *self.abiv2_mappings = unsafe {
            MemoryMapping::new_uninitialized(
                regions,
                executable.get_config(),
                executable.get_sbpf_version(),
                access_violation_handler,
            )
        };
    }

    pub fn set_abi_v2(&mut self) -> Result<(), InstructionError> {
        *self
            .contexts
            .last_mut()
            .ok_or(InstructionError::CallDepth)? = MemoryContextType::ABIv2;
        Ok(())
    }

    /// Modifies the memory regions as needed between any instruction edges.
    ///
    /// This function is to be called before execution changes between instructions: before a new
    /// program is executed, after a CPI return, etc.
    pub fn abi_v2_prepare_for_instruction(
        &mut self,
        transaction_context: &TransactionContext,
    ) -> Result<(), InstructionError> {
        let current_instruction = transaction_context.get_current_instruction_context()?;
        let regions = self.abiv2_mappings.get_regions_mut();

        // Before using the scratchpad the instruction has to call set_buffer_length syscall.
        // This is required in order to set the `program_id`.
        let return_data_scratchpad = regions
            .get_mut(RETURN_DATA_SCRATCHPAD_SECTION.region_index())
            .expect("return data scratchpad always present");
        return_data_scratchpad.writable = false;

        let accounts_in_transaction = transaction_context.accounts().len();
        let mut accounts_range = vm_addresses::ACCOUNT_PAYLOAD_SECTION.region_index_range();
        accounts_range.end = accounts_range.start.saturating_add(accounts_in_transaction);
        let account_regions = regions
            .get_mut(accounts_range)
            .expect("Account regions should have been configured.");

        for (tx_idx, acc_region) in account_regions.iter_mut().enumerate() {
            if let Ok(idx_in_ix) =
                current_instruction.get_index_of_account_in_instruction(tx_idx as IndexOfAccount)
            {
                let borrowed_account =
                    current_instruction.try_borrow_instruction_account(idx_in_ix)?;
                let can_data_be_changed = borrowed_account.can_data_be_changed();
                if can_data_be_changed.is_ok() && !acc_region.writable {
                    acc_region.access_violation_handler_payload = Some(tx_idx as IndexOfAccount);
                } else if can_data_be_changed.is_err() {
                    acc_region.access_violation_handler_payload = None;
                    acc_region.writable = false;
                }
            } else {
                acc_region.access_violation_handler_payload = None;
                acc_region.writable = false;
            }
        }

        Ok(())
    }
}

/// This structure contains metadata about the memory for each instruction under execution.
/// The BpfAllocator, accounts addresses in the guest and the memory mapping.
pub struct MemoryContext {
    pub allocator: BpfAllocator,
    pub accounts_metadata: Vec<SerializedAccountMetadata>,
    memory_mapping: Box<MemoryMapping>,
}

impl MemoryContext {
    /// Creates a new memory context
    pub fn new(
        allocator: BpfAllocator,
        accounts_metadata: Vec<SerializedAccountMetadata>,
        memory_mapping: MemoryMapping,
    ) -> Self {
        Self {
            allocator,
            accounts_metadata,
            memory_mapping: Box::new(memory_mapping),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SerializedAccountMetadata {
    /// Address of the first byte of the serialized account record (the
    /// `NON_DUP_MARKER`/duplicate-marker byte).
    pub vm_addr: u64,
    pub original_data_len: usize,
    pub vm_data_addr: u64,
    pub vm_key_addr: u64,
    pub vm_lamports_addr: u64,
    pub vm_owner_addr: u64,
}

#[cfg_attr(feature = "dev-context-only-utils", qualifier_attr::qualifiers(pub))]
pub(crate) fn create_abiv2_regions(
    transaction_context: &mut TransactionContext,
) -> Vec<MemoryRegion> {
    let mut v2_regions: Vec<MemoryRegion> =
        vec![MemoryRegion::default(); dbg!(vm_addresses::NUM_REGIONS)];

    // Filled on a later stage, but we still want to have at least base vm_addrs be accurate so that
    // there are no duplicate regions (for e.g. tests.)
    for section in [
        RODATA_SECTION,
        BYTECODE_SECTION,
        STACK_SECTION,
        HEAP_SECTION,
    ] {
        let region = v2_regions.get_mut(section.region_index()).unwrap();
        region.vm_addr = section.guest_address_range().start;
    }

    let section = TX_FRAME_SECTION;
    let tx_frame_region = MemoryRegion::new(
        transaction_context.transaction_frame_address(),
        section.guest_address_range().start,
    );
    *v2_regions.get_mut(section.region_index()).unwrap() = tx_frame_region;

    let section = ACCOUNT_METADATA_SECTION;
    let accounts_slice = transaction_context.accounts().shared_fields_as_raw_slice();
    *v2_regions.get_mut(section.region_index()).unwrap() =
        MemoryRegion::new(accounts_slice, section.guest_address_range().start);

    let section = INSTRUCTION_TRACE_SECTION;
    let instruction_trace_slice = transaction_context.instruction_trace_as_raw_slice();
    *v2_regions.get_mut(section.region_index()).unwrap() =
        MemoryRegion::new(instruction_trace_slice, section.guest_address_range().start);

    let section = RETURN_DATA_SCRATCHPAD_SECTION;
    let region = v2_regions.get_mut(section.region_index()).unwrap();
    *region = transaction_context.return_data_region();
    debug_assert_eq!(section.guest_address_range().start, region.vm_addr);

    let section = ACCOUNT_PAYLOAD_SECTION;
    let regions = v2_regions.get_mut(section.region_index_range()).unwrap();
    transaction_context
        .accounts()
        .account_payload_regions(regions);

    let section = SYSVAR_ACCOUNT_SECTION;
    let regions = v2_regions.get_mut(section.region_index_range()).unwrap();
    for (idx, region) in regions.iter_mut().enumerate() {
        // TODO: initialize the sysvar section fully?
        region.vm_addr = section.guest_address_range_for(idx).start;
    }

    let section = INSTRUCTION_DATA_SECTION;
    let regions = v2_regions.get_mut(section.region_index_range()).unwrap();
    transaction_context.instruction_payload_regions(regions);

    let section = INSTRUCTION_ACCOUNTS_SECTION;
    let regions = v2_regions
        .get_mut(dbg!(section.region_index_range()))
        .unwrap();
    transaction_context.instruction_accounts_regions(regions);

    dbg!(v2_regions)
}

#[cfg(test)]
mod test {
    use {
        crate::memory_context::{MemoryContexts, create_abiv2_regions},
        solana_account::AccountSharedData,
        solana_pubkey::Pubkey,
        solana_rent::Rent,
        solana_sbpf::{
            memory_region::{MemoryMapping, default_access_violation_handler},
            program::SBPFVersion,
            vm::Config,
        },
        solana_transaction_context::{
            instruction_accounts::InstructionAccount, transaction::TransactionContext, vm_addresses,
        },
    };

    #[test]
    fn test_update_account_permissions() {
        let program = Pubkey::new_unique();
        let accounts = vec![
            (
                Pubkey::new_unique(),
                AccountSharedData::new(20, 10, &program),
            ),
            (
                Pubkey::new_unique(),
                AccountSharedData::new(30, 15, &program),
            ),
            (
                Pubkey::new_unique(),
                AccountSharedData::new(40, 5, &program),
            ),
            (
                Pubkey::new_unique(),
                AccountSharedData::new(60, 2, &program),
            ),
            (
                program,
                AccountSharedData::new(20, 3, &Pubkey::new_unique()),
            ),
        ];

        let mut tx_context = TransactionContext::new(accounts, Rent::default(), 4, 64, 3);

        tx_context
            .configure_top_level_instruction_for_tests(
                4,
                vec![
                    InstructionAccount::new(0, false, false),
                    InstructionAccount::new(2, false, true),
                    InstructionAccount::new(1, false, false),
                    InstructionAccount::new(3, false, true),
                ],
                Vec::new(),
            )
            .unwrap();

        let mut memory_contexts = MemoryContexts::new();
        let abi_v2_regions = create_abiv2_regions(&mut tx_context);
        *memory_contexts.abiv2_mappings = unsafe {
            MemoryMapping::new_uninitialized(
                abi_v2_regions,
                &Config::default(),
                SBPFVersion::V4,
                Box::new(default_access_violation_handler),
            )
        };

        let accounts_range = vm_addresses::ACCOUNT_PAYLOAD_SECTION.region_index_range();

        // IX 1
        tx_context.push().unwrap();
        memory_contexts
            .abi_v2_prepare_for_instruction(&tx_context)
            .unwrap();
        let ix1_regions = memory_contexts
            .abiv2_mappings
            .get_regions()
            .get(accounts_range.clone())
            .unwrap();

        let reg_zero = ix1_regions.first().unwrap();
        assert!(reg_zero.access_violation_handler_payload.is_none());
        assert!(!reg_zero.writable);
        let reg_one = ix1_regions.get(1).unwrap();
        assert!(reg_one.access_violation_handler_payload.is_none());
        assert!(!reg_one.writable);
        let reg_two = ix1_regions.get(2).unwrap();
        assert_eq!(reg_two.access_violation_handler_payload, Some(2));
        assert!(!reg_two.writable);
        let reg_three = ix1_regions.get(3).unwrap();
        assert_eq!(reg_three.access_violation_handler_payload, Some(3));
        assert!(!reg_three.writable);
        for account_region in ix1_regions.iter().skip(4) {
            assert!(account_region.access_violation_handler_payload.is_none());
        }

        // IX 2
        tx_context.pop().unwrap();

        tx_context
            .configure_top_level_instruction_for_tests(
                4,
                vec![
                    InstructionAccount::new(1, false, false),
                    InstructionAccount::new(2, false, false),
                    InstructionAccount::new(0, false, true),
                ],
                Vec::new(),
            )
            .unwrap();
        tx_context.push().unwrap();

        memory_contexts
            .abi_v2_prepare_for_instruction(&tx_context)
            .unwrap();
        let ix2_regions = memory_contexts
            .abiv2_mappings
            .get_regions()
            .get(accounts_range.clone())
            .unwrap();

        let reg_zero = ix2_regions.first().unwrap();
        assert_eq!(reg_zero.access_violation_handler_payload, Some(0));
        assert!(!reg_zero.writable);
        let reg_one = ix2_regions.get(1).unwrap();
        assert!(reg_one.access_violation_handler_payload.is_none());
        assert!(!reg_one.writable);
        let reg_two = ix2_regions.get(2).unwrap();
        assert!(reg_two.access_violation_handler_payload.is_none());
        assert!(!reg_two.writable);
        let reg_three = ix2_regions.get(3).unwrap();
        assert!(reg_three.access_violation_handler_payload.is_none());
        assert!(!reg_three.writable);
        for account_region in ix2_regions.iter().skip(4) {
            assert!(account_region.access_violation_handler_payload.is_none());
        }

        // IX 3
        tx_context.pop().unwrap();

        tx_context
            .configure_top_level_instruction_for_tests(
                4,
                vec![
                    InstructionAccount::new(0, false, true),
                    InstructionAccount::new(1, false, true),
                    InstructionAccount::new(2, false, false),
                ],
                Vec::new(),
            )
            .unwrap();

        tx_context.push().unwrap();
        memory_contexts
            .abi_v2_prepare_for_instruction(&tx_context)
            .unwrap();
        let ix3_regions = memory_contexts
            .abiv2_mappings
            .get_regions()
            .get(accounts_range.clone())
            .unwrap();
        let reg_zero = ix3_regions.first().unwrap();
        assert_eq!(reg_zero.access_violation_handler_payload, Some(0));
        assert!(!reg_zero.writable);
        let reg_one = ix3_regions.get(1).unwrap();
        assert_eq!(reg_one.access_violation_handler_payload, Some(1));
        assert!(!reg_one.writable);
        let reg_two = ix3_regions.get(2).unwrap();
        assert!(reg_two.access_violation_handler_payload.is_none());
        assert!(!reg_two.writable);
        for account_region in ix3_regions.iter().skip(3) {
            assert!(account_region.access_violation_handler_payload.is_none());
        }

        // IX 3 again, but with region made writable
        let first_account = memory_contexts
            .abiv2_mappings
            .get_regions_mut()
            .get_mut(accounts_range.clone())
            .unwrap()
            .first_mut()
            .unwrap();
        first_account.writable = true;
        first_account.access_violation_handler_payload = None;
        memory_contexts
            .abi_v2_prepare_for_instruction(&tx_context)
            .unwrap();
        let ix3_regions = memory_contexts
            .abiv2_mappings
            .get_regions()
            .get(accounts_range.clone())
            .unwrap();
        let reg_zero = ix3_regions.first().unwrap();
        assert!(reg_zero.access_violation_handler_payload.is_none());
        assert!(reg_zero.writable);
        let reg_one = ix3_regions.get(1).unwrap();
        assert_eq!(reg_one.access_violation_handler_payload, Some(1));
        assert!(!reg_one.writable);
        let reg_two = ix3_regions.get(2).unwrap();
        assert!(reg_two.access_violation_handler_payload.is_none());
        assert!(!reg_two.writable);
        for account_region in ix3_regions.iter().skip(3) {
            assert!(account_region.access_violation_handler_payload.is_none());
        }
    }
}
