use std::io::Error;
use std::sync::Arc;
use crate::crypto::{build_corrupted_data_error, CryptoProcessor};
use crate::pman::id_value_map::IdValueMap;
use crate::pman::names_file::load_encryption_processor;
use crate::pman::pman_database_file::{decrypt_data, validate_data_hash, validate_data_hmac};

pub struct PasswordsFile {
    passwords: IdValueMap<String>
}

impl PasswordsFile {
    pub fn new(processor2: Arc<dyn CryptoProcessor>) -> PasswordsFile {
        PasswordsFile{passwords: IdValueMap::new(processor2)}
    }

    pub fn load(encryption_key: [u8; 32], alg1: u8, processor2: Arc<dyn CryptoProcessor>,
                data: Vec<u8>) -> Result<PasswordsFile, Error> {

        let l = validate_data_hash(&data)?;
        let l2 = validate_data_hmac(&encryption_key, &data, l)?;
        let (processor1, offset) = load_encryption_processor(alg1, encryption_key, &data)?;
        decrypt_data(processor1, &data, offset, l2);
        let mut passwords: IdValueMap<String> = IdValueMap::new(processor2);
        let offset2 = passwords.load(&data, offset)?;
        if offset2 != l2 {
            return Err(build_corrupted_data_error());
        }
        Ok(PasswordsFile{passwords})
    }

    pub fn save() {

    }
}