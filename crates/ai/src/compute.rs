//! Cortex-A76 `NEON` / `FEAT_DotProd` (`sdot`) Auto-Vectorized AI Compute Kernels.
//!
//! Compiled with `-C target-cpu=cortex-a76` (`+neon,+dotprod,+fp16`), LLVM lowers the 4-way
//! unrolled `i8` dot-product accumulators directly to ARMv8.2-A `sdot` SIMD instructions.

use newos_abi::SysError;

/// Quantized `i8` dot product (`sum(a[i] * b[i])`), structured in 4-element chunks so LLVM
/// emits Cortex-A76 `sdot` (`FEAT_DotProd`) instructions without any `unsafe` intrinsics.
///
/// # Errors
/// Returns [`SysError::InvalidArgument`] if `a.len() != b.len()`.
#[inline]
pub fn dot_i8(a: &[i8], b: &[i8]) -> Result<i32, SysError> {
    if a.len() != b.len() {
        return Err(SysError::InvalidArgument);
    }
    let (a_chunks, a_rem) = a.as_chunks::<4>();
    let (b_chunks, b_rem) = b.as_chunks::<4>();
    let mut acc = 0i32;
    for (ac, bc) in a_chunks.iter().zip(b_chunks.iter()) {
        acc = acc
            .wrapping_add(i32::from(ac[0]) * i32::from(bc[0]))
            .wrapping_add(i32::from(ac[1]) * i32::from(bc[1]))
            .wrapping_add(i32::from(ac[2]) * i32::from(bc[2]))
            .wrapping_add(i32::from(ac[3]) * i32::from(bc[3]));
    }
    for (&x, &y) in a_rem.iter().zip(b_rem.iter()) {
        acc = acc.wrapping_add(i32::from(x) * i32::from(y));
    }
    Ok(acc)
}

/// Quantized `i8` matrix-vector multiply: `out[r] = dot_i8(weights[r*cols..(r+1)*cols], input)`.
///
/// # Errors
/// Returns [`SysError::InvalidArgument`] if `cols == 0`, `input.len() != cols`, `out.len() != rows`,
/// or `rows.checked_mul(cols) != Some(weights.len())`.
pub fn matvec_i8(
    weights: &[i8],
    input: &[i8],
    rows: usize,
    cols: usize,
    out: &mut [i32],
) -> Result<(), SysError> {
    if cols == 0
        || input.len() != cols
        || out.len() != rows
        || rows.checked_mul(cols) != Some(weights.len())
    {
        return Err(SysError::InvalidArgument);
    }
    for (r, dst) in out.iter_mut().enumerate() {
        let row = &weights[r * cols..(r + 1) * cols];
        *dst = dot_i8(row, input)?;
    }
    Ok(())
}

/// `f32` matrix-vector multiply (`out = W * x`) for NEON `fmla` auto-vectorization.
///
/// # Errors
/// Returns [`SysError::InvalidArgument`] if `cols == 0`, `input.len() != cols`, `out.len() != rows`,
/// or `rows.checked_mul(cols) != Some(weights.len())`.
pub fn matvec_f32(
    weights: &[f32],
    input: &[f32],
    rows: usize,
    cols: usize,
    out: &mut [f32],
) -> Result<(), SysError> {
    if cols == 0
        || input.len() != cols
        || out.len() != rows
        || rows.checked_mul(cols) != Some(weights.len())
    {
        return Err(SysError::InvalidArgument);
    }
    for (r, dst) in out.iter_mut().enumerate() {
        let row = &weights[r * cols..(r + 1) * cols];
        let mut sum = 0.0f32;
        for (&w, &x) in row.iter().zip(input.iter()) {
            sum += w * x;
        }
        *dst = sum;
    }
    Ok(())
}

/// In-place `ReLU` activation (`x = max(0, x)`).
#[inline]
pub fn relu_inplace(data: &mut [f32]) {
    for x in data.iter_mut() {
        if *x < 0.0 {
            *x = 0.0;
        }
    }
}

/// Fast inverse square root (`1 / sqrt(x)`) via 3 Newton-Raphson iterations
/// (used for `rms_norm` without requiring `libm`).
#[inline]
fn inv_sqrt_f32(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    let i = 0x5f37_59dfu32.wrapping_sub(x.to_bits() >> 1);
    let mut y = f32::from_bits(i);
    let half = 0.5 * x;
    for _ in 0..3 {
        y *= 1.5 - half * y * y;
    }
    y
}

/// In-place `RMSNorm` (`x[i] = x[i] * weight[i] / sqrt(mean(x^2) + eps)`), standard in modern LLMs.
///
/// # Errors
/// Returns [`SysError::InvalidArgument`] if `x` is empty, `x.len() != weight.len()`, or `eps` is
/// negative or non-finite (`NaN`/`Inf`).
pub fn rms_norm_inplace(x: &mut [f32], weight: &[f32], eps: f32) -> Result<(), SysError> {
    if x.is_empty() || x.len() != weight.len() || !eps.is_finite() || eps < 0.0 {
        return Err(SysError::InvalidArgument);
    }
    let mut ss = 0.0f32;
    for &v in x.iter() {
        ss += v * v;
    }
    // Intentional: RMSNorm operates in f32 precision; tensor lengths <= 2^24 are exact in f32.
    #[allow(clippy::cast_precision_loss)]
    let denom = x.len() as f32;
    let scale = inv_sqrt_f32(ss / denom + eps);
    for (v, &w) in x.iter_mut().zip(weight.iter()) {
        *v *= scale * w;
    }
    Ok(())
}

/// Return the index of the maximum element in `logits` (or `None` if empty).
#[must_use]
pub fn argmax_f32(logits: &[f32]) -> Option<usize> {
    let mut best_idx = 0usize;
    let mut best_val = *logits.first()?;
    for (i, &v) in logits.iter().enumerate().skip(1) {
        if v > best_val {
            best_val = v;
            best_idx = i;
        }
    }
    Some(best_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_i8_and_matvec_i8_compute_exact_products() {
        let a = [1i8, -2, 3, -4, 5];
        let b = [10i8, 20, 30, 40, 50];
        // 10 - 40 + 90 - 160 + 250 = 150
        assert_eq!(dot_i8(&a, &b), Ok(150));
        assert_eq!(dot_i8(&a, &b[..4]), Err(SysError::InvalidArgument));

        let weights = [1i8, 2, 3, 4, -1, 0, 1, 2];
        let input = [2i8, 1, 0, -1];
        let mut out = [0i32; 2];
        matvec_i8(&weights, &input, 2, 4, &mut out).expect("matvec_i8");
        // row0: 2+2+0-4 = 0; row1: -2+0+0-2 = -4
        assert_eq!(out, [0, -4]);
    }

    #[test]
    fn matvec_relu_rms_norm_and_argmax_work_no_std() {
        let w = [1.0f32, -2.0, 3.0, 4.0];
        let x = [1.0f32, 2.0];
        let mut out = [0.0f32; 2];
        matvec_f32(&w, &x, 2, 2, &mut out).expect("matvec_f32");
        assert_eq!(out, [-3.0, 11.0]);
        relu_inplace(&mut out);
        assert_eq!(out, [0.0, 11.0]);
        assert_eq!(argmax_f32(&out), Some(1));

        let mut v = [3.0f32, 4.0];
        let gain = [1.0f32, 1.0];
        rms_norm_inplace(&mut v, &gain, 1e-6).expect("rms_norm_inplace");
        // rms = sqrt((9+16)/2) = sqrt(12.5) ~= 3.535534 -> v[1] ~= 1.13137
        assert!((v[1] - 1.13137).abs() < 0.001);
    }

    #[test]
    fn compute_kernels_validate_dimensions_eps_and_empty_inputs() {
        let mut int_out = [0i32; 2];
        assert_eq!(
            matvec_i8(&[1, 2], &[1], 2, 0, &mut int_out),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            matvec_i8(&[1, 2, 3], &[1, 2], 2, 2, &mut int_out),
            Err(SysError::InvalidArgument)
        );

        let mut float_out = [0.0f32; 2];
        assert_eq!(
            matvec_f32(&[1.0, 2.0], &[1.0], 2, 0, &mut float_out),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            matvec_f32(&[1.0, 2.0], &[1.0, 2.0], 2, 2, &mut float_out),
            Err(SysError::InvalidArgument)
        );

        let mut v = [1.0f32, 2.0];
        let gain = [1.0f32, 1.0];
        assert_eq!(
            rms_norm_inplace(&mut [], &[], 1e-6),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            rms_norm_inplace(&mut v, &[1.0], 1e-6),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            rms_norm_inplace(&mut v, &gain, -0.1),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            rms_norm_inplace(&mut v, &gain, f32::NAN),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(argmax_f32(&[]), None);
    }
}
