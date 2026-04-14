use std::fmt;

/// A wrapper type for sensitive values that prevents them from appearing in logs,
/// debug output, or error messages.
///
/// `Debug` and `Display` implementations always emit `[REDACTED]`.
/// The inner value is zeroized when dropped.
pub struct Redacted<T: zeroize::Zeroize> {
    inner: Option<T>,
}

impl<T: zeroize::Zeroize> Redacted<T> {
    /// Wrap a sensitive value.
    pub fn new(value: T) -> Self {
        Self { inner: Some(value) }
    }

    /// Access the inner value. Panics if `into_inner` was already called.
    pub fn expose(&self) -> &T {
        self.inner.as_ref().expect("Redacted value already consumed")
    }

    /// Consume and return the inner value (caller owns it, not zeroized).
    pub fn into_inner(mut self) -> T {
        self.inner.take().expect("Redacted value already consumed")
    }
}

impl<T: zeroize::Zeroize> Drop for Redacted<T> {
    fn drop(&mut self) {
        if let Some(ref mut v) = self.inner {
            v.zeroize();
        }
    }
}

impl<T: zeroize::Zeroize> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: zeroize::Zeroize> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = Redacted::new(String::from("my_secret_password"));
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn display_is_redacted() {
        let secret = Redacted::new(42u64);
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn expose_returns_inner() {
        let secret = Redacted::new(String::from("value"));
        assert_eq!(secret.expose(), "value");
    }

    #[test]
    fn into_inner_returns_value() {
        let secret = Redacted::new(99u8);
        assert_eq!(secret.into_inner(), 99);
    }
}
