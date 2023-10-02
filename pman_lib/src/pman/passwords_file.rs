use std::io::Error;
use std::sync::Arc;
use crate::crypto::CryptoProcessor;
use crate::pman::id_value_map::IdValueMap;
use crate::pman::pman_database_file::{build_encryption_key, decrypt_data, get_encryption_algorithms, validate_data_hmac};

pub struct PasswordsFile {
    processor: Arc<dyn CryptoProcessor>,
    passwords: IdValueMap<String>
}

impl PasswordsFile {
    pub fn load(header: &IdValueMap<Vec<u8>>, data: &Vec<u8>, offset: usize, length: usize) -> Result<PasswordsFile, Error>{
        let (alg1, alg2) = get_encryption_algorithms(&header)?;
        let encryption_key2 = build_encryption_key(&header, &password2_hash)?;
        let l2 = validate_data_hmac(&encryption_key2, &data, offset2, l)?;
        decrypt_data(alg1, &encryption_key2, &data, offset2, l2);
    }
}