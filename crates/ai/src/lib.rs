#![no_std]
#![forbid(unsafe_code)]

//! Pure `#![forbid(unsafe_code)]`, `no_alloc` Raspberry Pi 5 AI / NPU Compute Suite.
//!
//! Because BCM2712 does not include an integrated on-die NPU, AI acceleration on Raspberry Pi 5
//! (16 GB) is provided via two complementary paths:
//! - [`compute`]: Auto-vectorized ARMv8.2-A Cortex-A76 `NEON` + `FEAT_DotProd` (`sdot`) quantized
//!   `i8` & `f32` inference kernels (zero-heap, cache-blocked for 64 B lines).
//! - [`hailo`]: External PCIe 2.0 x1 FFC **Raspberry Pi AI HAT+ / AI Kit** NPU driver
//!   (**Hailo-8** 26 TOPS, **Hailo-8L** 13 TOPS, and **Hailo-10H**).

#[cfg(feature = "compute")]
pub mod compute;
#[cfg(feature = "hailo")]
pub mod hailo;
