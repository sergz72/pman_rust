use std::io::Error;
use std::sync::Arc;
use crate::crypto::{build_corrupted_data_error, CryptoProcessor};
use crate::pman::id_value_map::IdValueMap;
use crate::pman::ids::FILES_LOCATIONS_ID;
use crate::pman::names_file::{build_local_file_location, load_encryption_processor, load_file};
use crate::pman::pman_database_file::{decrypt_data, validate_data_hash, validate_data_hmac};
use crate::structs_interfaces::FileAction;

pub struct PasswordsFile {
    passwords: IdValueMap
}

impl PasswordsFile {
    pub fn new(processor2: Arc<dyn CryptoProcessor>) -> PasswordsFile {
        PasswordsFile{passwords: IdValueMap::new(processor2)}
    }

    pub fn load(encryption_key: [u8; 32], alg1: u8, processor2: Arc<dyn CryptoProcessor>,
                file_info: &IdValueMap) -> Result<PasswordsFile, Error> {

        let mut data = load_file(file_info)?;

        let l = validate_data_hash(&data)?;
        let l2 = validate_data_hmac(&encryption_key, &data, l)?;
        let (processor1, offset) = load_encryption_processor(alg1, encryption_key, &data)?;
        decrypt_data(processor1, &mut data, offset, l2)?;
        let mut passwords: IdValueMap = IdValueMap::new(processor2);
        let offset2 = passwords.load(&data, offset)?;
        if offset2 != l2 {
            return Err(build_corrupted_data_error());
        }
        Ok(PasswordsFile{passwords})
    }

    pub fn save(&self, file_name: String, encryption_key: [u8; 32], alg1: u8,
                processor2: Arc<dyn CryptoProcessor>,
                file_info: &IdValueMap) -> Result<Option<FileAction>, Error> {
        todo!()
    }

    pub fn save_remote(&self, file_name: String,
                       file_info: &IdValueMap) -> Result<Option<FileAction>, Error> {
        todo!()
    }

    pub fn build_file_info(processor2: Arc<dyn CryptoProcessor>) -> IdValueMap {
        let mut h = IdValueMap::new(processor2);
        h.add_with_id(FILES_LOCATIONS_ID, vec![FILES_LOCATIONS_ID as u8 + 1]).unwrap();
        h.add_with_id(FILES_LOCATIONS_ID+1, build_local_file_location()).unwrap();
        h
    }
}