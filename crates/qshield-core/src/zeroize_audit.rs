//! QS-114 -- Key zeroization audit: compile-time guarantees and tests.
//!
//! # What this module enforces
//!
//! 1. **No `Clone` on secret types** -- `static_assertions::assert_not_impl_any!`
//!    prevents accidental `Clone` derivation from ever compiling.
//!
//! 2. **`ZeroizeOnDrop` on all secret types** -- confirmed at compile time via
//!    `static_assertions::assert_impl_all!`.
//!
//! 3. **`mlock` utility** -- best-effort page-locking on Linux; no-op elsewhere.
//!
//! 4. **Manual memory inspection test** -- marked `#[ignore]`, run manually to
//!    spot-check that `SharedSecret` bytes are wiped on drop.

// -- mlock: best-effort page-locking ---------------------------------------

/// Attempt to lock `len` bytes at `ptr` in physical RAM (Linux only).
///
/// Prevents the page from being swapped to disk. Failure is non-fatal and is
/// logged at DEBUG level. No-op on Windows and macOS.
///
/// # Safety of the implementation
/// `mlock(2)` only reads the page boundaries around `ptr` -- it does not
/// dereference `ptr` itself. The call is safe even if `ptr` points to a
/// non-readable page (it will simply fail with `ENOMEM`).
#[cfg(target_os = "linux")]
pub fn mlock_best_effort(ptr: *const u8, len: usize) {
    use std::ffi::c_void;

    // SAFETY: sysconf is always safe; result is a page size power-of-2.
    let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
    let addr = (ptr as usize) & !(page_size - 1); // round down to page boundary
    let end = ptr as usize + len;
    let locked_len = end.saturating_sub(addr);

    // SAFETY: mlock(2) is safe to call; failure is non-fatal.
    let ret = unsafe { libc::mlock(addr as *const c_void, locked_len) };
    if ret != 0 {
        tracing::debug!(
            "mlock({:#x}, {}) failed (non-fatal): {}",
            addr,
            locked_len,
            std::io::Error::last_os_error()
        );
    }
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn mlock_best_effort(_ptr: *const u8, _len: usize) {}

// -- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DsaKeyPair, HybridSecretKey, KemSecretKey, SharedSecret};

    // -- Compile-time: secret types implement ZeroizeOnDrop ----------------
    // These expand to const assertions -- they fail at *compile* time if wrong.
    static_assertions::assert_impl_all!(SharedSecret: zeroize::ZeroizeOnDrop);
    static_assertions::assert_impl_all!(KemSecretKey: zeroize::ZeroizeOnDrop);
    static_assertions::assert_impl_all!(DsaKeyPair: zeroize::ZeroizeOnDrop);
    static_assertions::assert_impl_all!(HybridSecretKey: zeroize::ZeroizeOnDrop);

    // -- Compile-time: secret types do NOT implement Clone -----------------
    // If any of these types accidentally derive Clone, `cargo test` fails to compile.
    static_assertions::assert_not_impl_any!(SharedSecret: Clone);
    static_assertions::assert_not_impl_any!(KemSecretKey: Clone);
    static_assertions::assert_not_impl_any!(DsaKeyPair: Clone);
    static_assertions::assert_not_impl_any!(HybridSecretKey: Clone);

    #[test]
    fn mlock_does_not_panic() {
        let buf = [0u8; 64];
        // Must not panic on any platform.
        mlock_best_effort(buf.as_ptr(), buf.len());
    }

    #[test]
    fn secret_types_not_clone() {
        // Compile-time check already catches this; this test documents intent.
        // Uncommenting the following lines MUST produce a compile error:
        //   let kp = crate::kem_keygen(crate::KemLevel::Kem768).unwrap();
        //   let _ = kp.secret_key.clone();   // error[E0277]: Clone not satisfied
        //   let _ = kp.secret_key.level.clone();  // KemLevel IS Clone -- fine
    }

    /// Verify that `SharedSecret` bytes are zeroed after drop.
    ///
    /// Reads memory after drop -- technically undefined behaviour in Rust.
    /// Run manually only: `cargo test -- --ignored zeroize_after_drop`
    #[test]
    #[ignore = "reads memory after drop (UB) -- run manually to spot-check only"]
    fn zeroize_after_drop() {
        let secret = crate::kem::SharedSecret::from_raw([0xABu8; 32]);
        let ptr: *const u8 = secret.as_bytes().as_ptr();
        drop(secret);

        // SAFETY: we just owned this memory; zeroize should have wiped it.
        // This is UB per the Rust abstract machine -- manual inspection only.
        let bytes: [u8; 32] = unsafe { ptr.cast::<[u8; 32]>().read() };
        assert_eq!(bytes, [0u8; 32], "SharedSecret was not zeroed on drop");
    }
}
