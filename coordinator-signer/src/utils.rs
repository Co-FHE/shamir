use k256::elliptic_curve::ops::Reduce;
use k256::{elliptic_curve::bigint::U256, Scalar};
use rand::Rng;
use sha2::{Digest, Sha256};

/// Concatenates data and calculates their SHA256 hash
///
/// # Arguments
/// * `data` - Array of data that can be converted to bytes
///
/// # Returns
/// * `Vec<u8>` - Raw SHA256 hash bytes
pub fn concat_string_hash<T>(data: &[T]) -> Vec<u8>
where
    T: AsRef<[u8]>,
{
    // Create hasher
    let mut hasher = Sha256::new();

    // Update with each piece of data
    for d in data {
        hasher.update(d.as_ref());
    }

    // Return hash bytes
    hasher.finalize().to_vec()
}
pub fn random_readable_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        bytes.push(rng.gen::<u8>());
    }
    hex::encode(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concat_string_hash() {
        let result = concat_string_hash(&["Hello", "World"]);
        assert_eq!(result.len(), 64); // SHA256 hash is 64 characters long

        // Verify same input produces same hash
        let result2 = concat_string_hash(&["Hello", "World"]);
        assert_eq!(result, result2);
    }
}
