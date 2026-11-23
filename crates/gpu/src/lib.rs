#![no_std]
#![forbid(unsafe_code)]

//! Pure `#![forbid(unsafe_code)]`, `no_alloc` Raspberry Pi 5 Display, IOMMU & VideoCore VII GPU Suite.
//!
//! - [`FramebufferCanvas`]: Capability-scoped UEFI GOP linear 32-bit RGB framebuffer compositor
//! - [`iommu`]: Broadcom BCM2712 IOMMU (`brcm,bcm2712-iommu`) page-table & TLB driver
//! - [`v3d`]: Broadcom VideoCore VII (V3D 7.1) probe & Compute Shader Dispatch (CSD) driver

pub mod iommu;
pub mod v3d;

use newos_abi::SysError;

/// Capability-scoped 32-bit MMIO transport injected by EL0 `user-rt` or mock tests.
pub trait GpuMmioTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

/// Linear 32-bit UEFI GOP framebuffer geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FbGeometry {
    pub width: u32,
    pub height: u32,
    pub pitch_bytes: u32,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl FbGeometry {
    #[inline]
    pub const fn pack_rgb(self, r: u8, g: u8, b: u8) -> u32 {
        ((r as u32) << self.red_shift)
            | ((g as u32) << self.green_shift)
            | ((b as u32) << self.blue_shift)
    }
}

/// Capability-scoped EL0 linear 32-bit RGB framebuffer compositor (`CapId::BOOTSTRAP_FB_MMIO`).
pub struct FramebufferCanvas<T: GpuMmioTransport> {
    transport: T,
    geom: FbGeometry,
}

impl<T: GpuMmioTransport> FramebufferCanvas<T> {
    pub const fn new(transport: T, geom: FbGeometry) -> Self {
        Self { transport, geom }
    }

    #[inline]
    pub const fn geometry(&self) -> FbGeometry {
        self.geom
    }

    /// Plot a single clipped pixel at `(x, y)` with `(r, g, b)`.
    pub fn draw_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) -> Result<(), SysError> {
        if x >= self.geom.width || y >= self.geom.height {
            return Ok(());
        }
        let off = u64::from(y)
            .saturating_mul(u64::from(self.geom.pitch_bytes))
            .saturating_add(u64::from(x) * 4);
        self.transport.write32(off, self.geom.pack_rgb(r, g, b))
    }

    /// Fill a clipped rectangle `(x, y, w, h)` with solid `rgb = (r, g, b)`.
    pub fn fill_rect(
        &self,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        rgb: (u8, u8, u8),
    ) -> Result<(), SysError> {
        let pixel = self.geom.pack_rgb(rgb.0, rgb.1, rgb.2);
        let x_end = x.saturating_add(w).min(self.geom.width);
        let y_end = y.saturating_add(h).min(self.geom.height);
        for row in y..y_end {
            let row_base = u64::from(row).saturating_mul(u64::from(self.geom.pitch_bytes));
            for col in x..x_end {
                self.transport
                    .write32(row_base + u64::from(col) * 4, pixel)?;
            }
        }
        Ok(())
    }

    /// Clear the entire framebuffer to `(r, g, b)`.
    pub fn clear(&self, r: u8, g: u8, b: u8) -> Result<(), SysError> {
        self.fill_rect(0, 0, self.geom.width, self.geom.height, (r, g, b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockFb {
        pixels: RefCell<[u32; 16]>,
    }

    impl GpuMmioTransport for &MockFb {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            Ok(self.pixels.borrow()[(offset / 4) as usize])
        }
        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            self.pixels.borrow_mut()[(offset / 4) as usize] = val;
            Ok(())
        }
    }

    #[test]
    fn framebuffer_canvas_packs_rgb_and_clips_bounds() {
        let mock = MockFb {
            pixels: RefCell::new([0; 16]),
        };
        let geom = FbGeometry {
            width: 4,
            height: 4,
            pitch_bytes: 16,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        };
        let fb = FramebufferCanvas::new(&mock, geom);
        fb.fill_rect(1, 1, 2, 2, (0x12, 0x34, 0x56)).unwrap();
        // Out-of-bounds draw clips cleanly without error
        fb.draw_pixel(99, 99, 0xFF, 0xFF, 0xFF).unwrap();
        assert_eq!(mock.pixels.borrow()[5], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[6], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[9], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[10], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[0], 0);
    }
}
