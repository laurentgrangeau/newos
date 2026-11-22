#![forbid(unsafe_code)]

//! Opaque-box E2E test suite for `newos-abi` and `newos-kernel-core`.
//!
//! Compile & run offline with:
//! ```bash
//! rustc --edition 2024 --test --crate-name e2e_kernel tests/e2e/e2e_kernel.rs \
//!   -L dependency=target/e2e \
//!   --extern newos_abi=target/e2e/libnewos_abi.rlib \
//!   --extern newos_kernel_core=target/e2e/libnewos_kernel_core.rlib \
//!   -o target/e2e/e2e_kernel
//! ./target/e2e/e2e_kernel
//! ```

pub(crate) mod test_helpers {
    use newos_abi::SysError;
    use newos_kernel_core::memory::{
        PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, UntypedInventory, VSpaceMapper, VirtAddr,
    };
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// Returns the ELF64 `e_machine` value expected by `newos_kernel_core::elf::parse_elf64`
    /// on the current compilation target.
    pub fn host_elf_machine() -> u16 {
        if cfg!(target_arch = "aarch64") {
            183
        } else {
            62
        }
    }

    /// Returns the opposite architecture's `e_machine` for negative tests.
    pub fn wrong_elf_machine() -> u16 {
        if cfg!(target_arch = "aarch64") {
            62
        } else {
            183
        }
    }

    /// Specification for one ELF64 program header entry.
    #[derive(Clone, Copy)]
    pub struct PhdrSpec {
        pub p_type: u32,
        pub p_flags: u32,
        pub p_offset: u64,
        pub p_vaddr: u64,
        pub p_filesz: u64,
        pub p_memsz: u64,
    }

    /// Builds a synthetic little-endian ELF64 image with configurable header fields and phdrs.
    pub fn build_elf64(
        entry: u64,
        e_type: u16,
        e_machine: u16,
        phentsize: u16,
        phdrs: &[PhdrSpec],
        payload: &[u8],
    ) -> Vec<u8> {
        let phoff: u64 = 64;
        let ph_table_len = (phentsize as usize) * phdrs.len();
        let min_len = 64 + ph_table_len;
        let total_len = min_len.max(64 + ph_table_len + payload.len());
        let mut buf = vec![0u8; total_len];

        // e_ident: magic, ELFCLASS64 (2), ELFDATA2LSB (1), EV_CURRENT (1)
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;

        buf[16..18].copy_from_slice(&e_type.to_le_bytes());
        buf[18..20].copy_from_slice(&e_machine.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        buf[24..32].copy_from_slice(&entry.to_le_bytes());
        buf[32..40].copy_from_slice(&phoff.to_le_bytes());
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf[54..56].copy_from_slice(&phentsize.to_le_bytes());
        buf[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());

        for (idx, ph) in phdrs.iter().enumerate() {
            let base = 64 + idx * (phentsize as usize);
            buf[base..base + 4].copy_from_slice(&ph.p_type.to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&ph.p_flags.to_le_bytes());
            buf[base + 8..base + 16].copy_from_slice(&ph.p_offset.to_le_bytes());
            buf[base + 16..base + 24].copy_from_slice(&ph.p_vaddr.to_le_bytes());
            buf[base + 24..base + 32].copy_from_slice(&ph.p_vaddr.to_le_bytes()); // p_paddr
            buf[base + 32..base + 40].copy_from_slice(&ph.p_filesz.to_le_bytes());
            buf[base + 40..base + 48].copy_from_slice(&ph.p_memsz.to_le_bytes());
            buf[base + 48..base + 56].copy_from_slice(&PAGE_SIZE.to_le_bytes()); // p_align
        }

        let payload_start = 64 + ph_table_len;
        buf[payload_start..payload_start + payload.len()].copy_from_slice(payload);
        buf
    }

    /// Host-side mock `VSpaceMapper` storing 4 KiB frame backing buffers in memory
    /// so ELF64 loading, W^X enforcement, and BSS zeroing can be verified end-to-end.
    pub struct MockVSpaceMapper {
        root: PhysAddr,
        mappings: BTreeMap<u64, (PhysAddr, PageFlags)>,
        frames: RefCell<BTreeMap<u64, [u8; PAGE_SIZE as usize]>>,
    }

    impl MockVSpaceMapper {
        pub fn new(root: PhysAddr) -> Self {
            Self {
                root,
                mappings: BTreeMap::new(),
                frames: RefCell::new(BTreeMap::new()),
            }
        }

        pub fn read_frame_slice(&self, phys: PhysAddr, offset: usize, len: usize) -> Vec<u8> {
            let frames = self.frames.borrow();
            let page = frames
                .get(&phys.raw())
                .expect("physical frame must exist in mock RAM");
            page[offset..offset + len].to_vec()
        }

        pub fn mapping_count(&self) -> usize {
            self.mappings.len()
        }
    }

    impl VSpaceMapper for MockVSpaceMapper {
        fn root_phys(&self) -> PhysAddr {
            self.root
        }

        fn map_4k(
            &mut self,
            virt: VirtAddr,
            frame: PhysFrame,
            flags: PageFlags,
            _untyped: &mut UntypedInventory,
        ) -> Result<(), SysError> {
            if !virt.is_page_aligned() {
                return Err(SysError::InvalidArgument);
            }
            if flags.writable && flags.executable {
                return Err(SysError::InvalidArgument);
            }
            if self.mappings.contains_key(&virt.raw()) {
                return Err(SysError::SlotOccupied);
            }
            let phys = frame.start_addr();
            self.frames
                .borrow_mut()
                .entry(phys.raw())
                .or_insert([0xAAu8; PAGE_SIZE as usize]);
            self.mappings.insert(virt.raw(), (phys, flags));
            Ok(())
        }

        fn translate(&self, virt: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
            let page_base = virt.raw() & !(PAGE_SIZE - 1);
            let offset = virt.raw() & (PAGE_SIZE - 1);
            self.mappings
                .get(&page_base)
                .map(|(phys, flags)| (PhysAddr::new(phys.raw() + offset), *flags))
        }

        fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysFrame, SysError> {
            let (phys, _) = self
                .mappings
                .remove(&virt.raw())
                .ok_or(SysError::InvalidArgument)?;
            PhysFrame::from_aligned(phys)
        }

        fn zero_frame(&self, frame: &PhysFrame) {
            self.frames
                .borrow_mut()
                .insert(frame.start_addr().raw(), [0u8; PAGE_SIZE as usize]);
        }

        fn write_frame_bytes(
            &self,
            frame: &PhysFrame,
            offset: usize,
            src: &[u8],
        ) -> Result<(), SysError> {
            if offset + src.len() > PAGE_SIZE as usize {
                return Err(SysError::InvalidArgument);
            }
            let mut frames = self.frames.borrow_mut();
            let page = frames
                .entry(frame.start_addr().raw())
                .or_insert([0u8; PAGE_SIZE as usize]);
            page[offset..offset + src.len()].copy_from_slice(src);
            Ok(())
        }
    }
}

#[path = "kernel/tier1_core.rs"]
mod tier1_core;

#[path = "kernel/tier2_errors.rs"]
mod tier2_errors;

#[path = "kernel/tier3_integration.rs"]
mod tier3_integration;

#[path = "kernel/tier4_invariants.rs"]
mod tier4_invariants;
