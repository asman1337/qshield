use uuid::Uuid;

/// Generate a new UUIDv7 identifier.
///
/// UUIDv7 is time-ordered (monotonically increasing), making it safe for use
/// as database primary keys without enumeration attacks (unlike auto-increment integers).
///
/// # Example
/// ```
/// use qshield_common::new_id;
/// let id = new_id();
/// assert_eq!(id.get_version_num(), 7);
/// ```
#[must_use]
pub fn new_id() -> Uuid {
    Uuid::now_v7()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_v7() {
        let id = new_id();
        assert_eq!(id.get_version_num(), 7);
    }

    #[test]
    fn ids_are_time_ordered() {
        let a = new_id();
        let b = new_id();
        // UUIDv7 bytes are lexicographically ordered by time
        assert!(a.as_bytes() <= b.as_bytes());
    }
}
