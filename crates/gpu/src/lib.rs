#![no_std]

//! Raspberry Pi 5 Display, IOMMU & `VideoCore` VII GPU Suite.
//!
//! - [`FramebufferCanvas`]: Capability-scoped UEFI GOP linear 32-bit RGB framebuffer compositor
//! - [`iommu`]: Broadcom BCM2712 IOMMU (`brcm,bcm2712-iommu`) page-table & TLB driver
//! - [`v3d`]: Broadcom `VideoCore` VII (V3D 7.1) probe & Compute Shader Dispatch (CSD) driver

#[cfg(feature = "iommu")]
pub mod iommu;
#[cfg(feature = "v3d")]
pub mod v3d;

use newos_abi::SysError;

/// Capability-scoped 32-bit MMIO transport injected by EL0 `user-rt` or mock tests.
pub trait GpuMmioTransport {
    /// Read a 32-bit register at `offset` within the scoped GPU/display MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write a 32-bit register at `offset` within the scoped GPU/display MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

/// 24-bit sRGB color value for framebuffer drawing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    /// Construct an [`Rgb`] color from `(r, g, b)` channel intensities.
    #[inline]
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

impl From<(u8, u8, u8)> for Rgb {
    #[inline]
    fn from((r, g, b): (u8, u8, u8)) -> Self {
        Self { r, g, b }
    }
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
    /// Pack an [`Rgb`] color into a 32-bit pixel word according to the framebuffer channel shifts.
    ///
    /// Channel shifts are masked to `0..=31` to guarantee shift-overflow panic freedom.
    #[inline]
    #[must_use]
    pub const fn pack_rgb(self, color: Rgb) -> u32 {
        ((color.r as u32) << (self.red_shift & 31))
            | ((color.g as u32) << (self.green_shift & 31))
            | ((color.b as u32) << (self.blue_shift & 31))
    }
}

/// Capability-scoped EL0 linear 32-bit RGB framebuffer compositor (`CapId::BOOTSTRAP_FB_MMIO`).
#[derive(Debug)]
pub struct FramebufferCanvas<T: GpuMmioTransport> {
    transport: T,
    geom: FbGeometry,
}

impl<T: GpuMmioTransport> FramebufferCanvas<T> {
    /// Construct a framebuffer canvas bound to `transport` and `geom`.
    #[must_use]
    pub const fn new(transport: T, geom: FbGeometry) -> Self {
        Self { transport, geom }
    }

    /// Return the framebuffer geometry descriptor.
    #[inline]
    #[must_use]
    pub const fn geometry(&self) -> FbGeometry {
        self.geom
    }

    /// Plot a single clipped pixel at `(x, y)` with `color`.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO write fails.
    pub fn draw_pixel(&self, x: u32, y: u32, color: Rgb) -> Result<(), SysError> {
        if x >= self.geom.width || y >= self.geom.height {
            return Ok(());
        }
        let off = u64::from(y)
            .saturating_mul(u64::from(self.geom.pitch_bytes))
            .saturating_add(u64::from(x) * 4);
        self.transport.write32(off, self.geom.pack_rgb(color))
    }

    /// Fill a clipped rectangle `(x, y, w, h)` with solid `color`.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if any MMIO write fails.
    pub fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, color: Rgb) -> Result<(), SysError> {
        let pixel = self.geom.pack_rgb(color);
        let x_end = x.saturating_add(w).min(self.geom.width);
        let y_end = y.saturating_add(h).min(self.geom.height);
        for row in y..y_end {
            let row_base = u64::from(row).saturating_mul(u64::from(self.geom.pitch_bytes));
            for col in x..x_end {
                self.transport
                    .write32(row_base.saturating_add(u64::from(col) * 4), pixel)?;
            }
        }
        Ok(())
    }

    /// Clear the entire framebuffer to `color`.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if any MMIO write fails.
    pub fn clear(&self, color: Rgb) -> Result<(), SysError> {
        self.fill_rect(0, 0, self.geom.width, self.geom.height, color)
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
        fb.fill_rect(1, 1, 2, 2, Rgb::from((0x12, 0x34, 0x56)))
            .expect("fill_rect");
        // Out-of-bounds draw clips cleanly without error
        fb.draw_pixel(99, 99, Rgb::new(0xFF, 0xFF, 0xFF))
            .expect("clipped draw_pixel");
        assert_eq!(mock.pixels.borrow()[5], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[6], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[9], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[10], 0x0012_3456);
        assert_eq!(mock.pixels.borrow()[0], 0);

        // Guarded shift avoids panic even if shift >= 32
        let extreme = FbGeometry {
            red_shift: 32,
            green_shift: 40,
            blue_shift: 48,
            ..geom
        };
        let _ = extreme.pack_rgb(Rgb::default());
    }

    #[test]
    fn fill_rect_saturates_u64_offset_without_overflow_panic() {
        struct RecordingTransport {
            last_offset: RefCell<Option<u64>>,
        }

        impl GpuMmioTransport for &RecordingTransport {
            fn read32(&self, _offset: u64) -> Result<u32, SysError> {
                Ok(0)
            }
            fn write32(&self, offset: u64, _val: u32) -> Result<(), SysError> {
                *self.last_offset.borrow_mut() = Some(offset);
                Ok(())
            }
        }

        let transport = RecordingTransport {
            last_offset: RefCell::new(None),
        };
        let geom = FbGeometry {
            width: u32::MAX,
            height: u32::MAX,
            pitch_bytes: u32::MAX,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        };
        let fb = FramebufferCanvas::new(&transport, geom);
        fb.fill_rect(u32::MAX - 1, u32::MAX - 1, 1, 1, Rgb::new(0x11, 0x22, 0x33))
            .expect("fill_rect with extreme geometry must not overflow");
        assert_eq!(*transport.last_offset.borrow(), Some(u64::MAX));
    }
}
