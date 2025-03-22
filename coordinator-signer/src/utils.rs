use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;
/// Concatenates data and calculates their SHA256 hash
///
/// # Arguments
/// * `data` - Array of data that can be converted to bytes
///
/// # Returns
/// * `Vec<u8>` - Raw SHA256 hash bytes
pub(crate) fn list_hash<T>(data: &[T]) -> Vec<u8>
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
pub(crate) fn random_readable_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        bytes.push(rng.gen::<u8>());
    }
    hex::encode(bytes)
}

pub(crate) fn new_oneshot_to_receive_success_or_error<T: std::fmt::Debug + Send + 'static>(
) -> oneshot::Sender<T> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = rx.await;
        match result {
            Ok(result) => tracing::debug!("oneshot received result: {:?}", result),
            Err(e) => tracing::warn!("oneshot received closed: {:?}", e),
        }
    });

    tx
}
pub(crate) fn derived_data(data: Option<Vec<u8>>) -> Vec<u8> {
    if let Some(data) = data {
        data
    } else {
        vec![
            119, 104, 111, 32, 105, 115, 32, 115, 104, 105, 111, 116, 111, 108, 105, 63,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_hash() {
        let result = list_hash(&["Hello", "World"]);
        assert_eq!(result.len(), 32); // SHA256 hash is 64 characters long

        // Verify same input produces same hash
        let result2 = list_hash(&["Hello", "World"]);
        assert_eq!(result, result2);
    }
}
