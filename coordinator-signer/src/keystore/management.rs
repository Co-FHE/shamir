use super::Keystore;
use super::KeystoreError;
use file_lock::FileLock;
use file_lock::FileOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
pub(crate) struct KeystoreManagement {
    keystore: Arc<Keystore>,
    path: PathBuf,
    tmp_path: PathBuf,
}
impl KeystoreManagement {
    pub(crate) fn new(
        keystore: Arc<Keystore>,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(Self, Option<Vec<u8>>), KeystoreError> {
        //path join {sha256 of key}.keystore
        let path = path.as_ref();
        let path = path.join(format!(
            "{}.keystore",
            hex::encode(keystore.as_ref().original_hash())
        ));
        let tmp_path = path.with_file_name(format!(
            "{}.backup.keystore",
            hex::encode(keystore.as_ref().original_hash())
        ));
        if tmp_path.exists() {
            return Err(KeystoreError::BackupFileExists(
                tmp_path.display().to_string(),
            ));
        }
        let data = if !path.exists() {
            std::fs::create_dir_all(path.parent().unwrap())?;

            None
        } else {
            //read the file and decrypt it
            let ciphertext = std::fs::read(path.clone())?;

            let data = keystore.decrypt(ciphertext)?;
            Some(data)
        };
        println!("data: {:?}", data);
        println!("path: {:?}", path);
        println!("tmp_path: {:?}", tmp_path);
        Ok((
            Self {
                keystore,
                path: path.clone(),
                tmp_path: tmp_path.clone(),
            },
            data,
        ))
    }
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<(), KeystoreError> {
        if self.tmp_path.exists() {
            return Err(KeystoreError::BackupFileExists(
                self.tmp_path.display().to_string(),
            ));
        }
        if self.path.exists() {
            std::fs::copy(self.path.clone(), self.tmp_path.clone())?;
        }
        let ciphertext = self.keystore.as_ref().encrypt(data)?;
        let opts = FileOptions::new().write(true).create(true).truncate(true);
        let mut lock = FileLock::lock(self.path.clone(), true, opts)?;
        lock.file.write_all(&ciphertext)?;
        lock.unlock()?;
        //remove the tmp_path
        if self.tmp_path.exists() {
            std::fs::remove_file(self.tmp_path.clone())?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::PathBuf, sync::Arc};

    #[test]
    fn test_keystore_management() {
        let keystore = Arc::new(Keystore::new(b"test", None).unwrap());
        let path = PathBuf::from(".test");
        let (mut keystore, decrypted_data) =
            KeystoreManagement::new(keystore, path.clone()).unwrap();
        println!("decrypted_data: {:?}", decrypted_data);
        let data = b"aaa";
        keystore.write(data).unwrap();
        let keystore1 = Arc::new(Keystore::new(b"test", None).unwrap());
        let (mut keystore1, decrypted_data) =
            KeystoreManagement::new(keystore1, path.clone()).unwrap();
        println!("decrypted_data: {:?}", decrypted_data);
        assert_eq!(decrypted_data, Some(b"aaa".to_vec()));
        let data = b"test";
        keystore1.write(data).unwrap();
    }
}
