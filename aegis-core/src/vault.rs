//! An unlocked vault: decrypted contents plus everything needed to save it.

use crate::format::{self, KdfParams, Key, SALT_LEN};
use crate::model::PasswordList;

pub struct UnlockedVault {
    pub list: PasswordList,
    key: Key,
    salt: [u8; SALT_LEN],
    params: KdfParams,
}

impl UnlockedVault {
    /// Decrypt vault file bytes.
    pub fn open(data: &[u8], password: &str, keyfile: Option<&[u8]>) -> Result<Self, String> {
        let opened = format::open(data, password, keyfile)?;
        let list = PasswordList::from_json(&opened.plaintext)?;
        Ok(Self {
            list,
            key: opened.key,
            salt: opened.salt,
            params: opened.params,
        })
    }

    /// A new, empty vault with a fresh salt.
    pub fn create(
        password: &str,
        params: KdfParams,
        keyfile: Option<&[u8]>,
    ) -> Result<Self, String> {
        let salt = format::random_salt();
        let key = format::derive_key(password, &salt, params, keyfile)?;
        Ok(Self {
            list: PasswordList::default(),
            key,
            salt,
            params,
        })
    }

    /// Encrypt the current contents into vault file bytes. Keeps the salt and
    /// KDF params, so the same master password keeps working.
    pub fn seal(&self) -> Result<Vec<u8>, String> {
        let json = self.list.to_json()?;
        format::seal(&json, &self.key, &self.salt, self.params)
    }

    /// Re-key with a new master password (and fresh salt).
    pub fn change_password(
        &mut self,
        new_password: &str,
        keyfile: Option<&[u8]>,
    ) -> Result<(), String> {
        let salt = format::random_salt();
        self.key = format::derive_key(new_password, &salt, self.params, keyfile)?;
        self.salt = salt;
        Ok(())
    }

    pub fn params(&self) -> KdfParams {
        self.params
    }
}
