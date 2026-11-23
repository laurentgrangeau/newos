//! Broadcom VideoCore VII (V3D 7.1) GPU Probe & Compute Shader Dispatch.
//!
//! Physical MMIO layout on Raspberry Pi 5 (BCM2712):
//! - `V3D_HUB`:   `0x10_0200_0000` (offset `+0x0000`) — `IDENT0..3`, MMU control
//! - `V3D_CORE0`: `0x10_0200_8000` (offset `+0x8000`) — `IDENT0..2`, CSD Compute Shader Dispatch

use crate::GpuMmioTransport;
use newos_abi::SysError;

pub const BCM2712_V3D_PHYS: u64 = 0x10_0200_0000;
pub const V3D_HUB_OFF: u64 = 0x0000;
pub const V3D_CORE0_OFF: u64 = 0x8000;

// V3D Hub Register Offsets
pub const V3D_HUB_IDENT0: u64 = V3D_HUB_OFF;
pub const V3D_HUB_IDENT1: u64 = V3D_HUB_OFF + 0x004;
pub const V3D_MMU_CTL: u64 = V3D_HUB_OFF + 0x1200;

// V3D Core 0 Register Offsets
pub const V3D_CORE_IDENT0: u64 = V3D_CORE0_OFF;
pub const V3D_CORE_IDENT1: u64 = V3D_CORE0_OFF + 0x004;
pub const V3D_CSD_STATUS: u64 = V3D_CORE0_OFF + 0x900;
pub const V3D_CSD_QUEUED_CFG0: u64 = V3D_CORE0_OFF + 0x904;
pub const V3D_CSD_QUEUED_CFG1: u64 = V3D_CORE0_OFF + 0x908;
pub const V3D_CSD_QUEUED_CFG2: u64 = V3D_CORE0_OFF + 0x90C;
pub const V3D_CSD_QUEUED_CFG3: u64 = V3D_CORE0_OFF + 0x910;
pub const V3D_CSD_QUEUED_CFG4: u64 = V3D_CORE0_OFF + 0x914;
pub const V3D_CSD_QUEUED_CFG5: u64 = V3D_CORE0_OFF + 0x918;
pub const V3D_CSD_QUEUED_CFG6: u64 = V3D_CORE0_OFF + 0x91C;

/// Expected ASCII magic in `V3D_HUB_IDENT0` (`"V3D\0"` -> `0x0044_3356` low 24 bits).
pub const V3D_IDENT0_MAGIC: u32 = 0x0044_3356;

/// Probed VideoCore VII (V3D 7.1) hardware topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3dInfo {
    pub tech_version: u8,
    pub revision: u8,
    pub num_cores: u8,
    pub num_slices: u8,
    pub num_tmus: u8,
}

/// V3D 7.1 Compute Shader Dispatch (`CSD`) job descriptor (`CFG0..CFG6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsdJobConfig {
    pub cfg0_wg_x: u32,
    pub cfg1_wg_y: u32,
    pub cfg2_wg_z: u32,
    pub cfg3_wg_size: u32,
    pub cfg4_batches: u32,
    pub cfg5_shader_addr: u32,
    pub cfg6_uniform_addr: u32,
}

/// Capability-scoped EL0 VideoCore VII (V3D 7.1) driver (`CapId::BOOTSTRAP_V3D_MMIO`).
pub struct VideoCoreV3d<T: GpuMmioTransport> {
    transport: T,
}

impl<T: GpuMmioTransport> VideoCoreV3d<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Probe `V3D_HUB_IDENT0/1` and `V3D_CORE_IDENT1`, returning `V3dInfo` if VideoCore VII is present.
    pub fn probe(&self) -> Result<V3dInfo, SysError> {
        let hub0 = self.transport.read32(V3D_HUB_IDENT0)?;
        if (hub0 & 0x00FF_FFFF) != V3D_IDENT0_MAGIC {
            return Err(SysError::Unsupported);
        }
        let hub1 = self.transport.read32(V3D_HUB_IDENT1)?;
        let tech_version = ((hub1 >> 4) & 0xF) as u8;
        let revision = (hub1 & 0xF) as u8;
        let num_cores = ((hub1 >> 8) & 0xF) as u8;

        let core1 = self.transport.read32(V3D_CORE_IDENT1)?;
        let num_slices = ((core1 >> 4) & 0xF) as u8;
        let num_tmus = ((core1 >> 12) & 0xF) as u8;

        Ok(V3dInfo {
            tech_version,
            revision,
            num_cores,
            num_slices,
            num_tmus,
        })
    }

    /// Submit a Compute Shader Dispatch (`CSD`) job to V3D 7.1 Core 0.
    ///
    /// Writing `CFG6` commits the queued job to the V3D CSD hardware queue.
    pub fn dispatch_compute(&self, job: CsdJobConfig) -> Result<(), SysError> {
        self.transport.write32(V3D_CSD_QUEUED_CFG0, job.cfg0_wg_x)?;
        self.transport.write32(V3D_CSD_QUEUED_CFG1, job.cfg1_wg_y)?;
        self.transport.write32(V3D_CSD_QUEUED_CFG2, job.cfg2_wg_z)?;
        self.transport
            .write32(V3D_CSD_QUEUED_CFG3, job.cfg3_wg_size)?;
        self.transport
            .write32(V3D_CSD_QUEUED_CFG4, job.cfg4_batches)?;
        self.transport
            .write32(V3D_CSD_QUEUED_CFG5, job.cfg5_shader_addr)?;
        self.transport
            .write32(V3D_CSD_QUEUED_CFG6, job.cfg6_uniform_addr)
    }

    /// Read `V3D_CSD_STATUS` (bit 0 = queue full, bits 11:4 = completed jobs).
    pub fn csd_status(&self) -> Result<u32, SysError> {
        self.transport.read32(V3D_CSD_STATUS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockV3d {
        dispatches: RefCell<u32>,
    }

    impl GpuMmioTransport for &MockV3d {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                V3D_HUB_IDENT0 => Ok(V3D_IDENT0_MAGIC),
                // V3D 7.1, 1 core
                V3D_HUB_IDENT1 => Ok((1 << 8) | (7 << 4) | 1),
                // 3 slices, 3 TMUs
                V3D_CORE_IDENT1 => Ok((3 << 12) | (3 << 4)),
                V3D_CSD_STATUS => Ok(0),
                _ => Ok(0),
            }
        }
        fn write32(&self, offset: u64, _val: u32) -> Result<(), SysError> {
            if offset == V3D_CSD_QUEUED_CFG6 {
                *self.dispatches.borrow_mut() += 1;
            }
            Ok(())
        }
    }

    #[test]
    fn v3d_probes_videocore7_and_dispatches_compute_job() {
        let mock = MockV3d {
            dispatches: RefCell::new(0),
        };
        let gpu = VideoCoreV3d::new(&mock);
        let info = gpu.probe().expect("probe V3D 7.1");
        assert_eq!(info.tech_version, 7);
        assert_eq!(info.revision, 1);
        assert_eq!(info.num_cores, 1);
        assert_eq!(info.num_slices, 3);

        gpu.dispatch_compute(CsdJobConfig {
            cfg0_wg_x: 16,
            cfg1_wg_y: 1,
            cfg2_wg_z: 1,
            cfg3_wg_size: 64,
            cfg4_batches: 1,
            cfg5_shader_addr: 0x0010_0000,
            cfg6_uniform_addr: 0x0011_0000,
        })
        .expect("dispatch compute");
        assert_eq!(*mock.dispatches.borrow(), 1);
    }
}
