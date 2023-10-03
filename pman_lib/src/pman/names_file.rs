use std::io::Error;
use std::sync::Arc;
use crate::crypto::{build_corrupted_data_error, CryptoProcessor};
use crate::pman::header_entity::HeaderEntity;
use crate::pman::id_value_map::IdValueMap;
use crate::pman::pman_database_file::{decrypt_data, validate_data_hash, validate_data_hmac};

pub struct NamesFile {
    entities: IdValueMap<HeaderEntity>,
    names: IdValueMap<String>
}

impl NamesFile {
    pub fn new(processor2: Arc<dyn CryptoProcessor>) -> NamesFile {
        NamesFile{entities: IdValueMap::new(processor2.clone()),
            names: IdValueMap::new(processor2)}
    }

    pub fn load(encryption_key: [u8; 32], alg1: u8, processor2: Arc<dyn CryptoProcessor>,
                data: Vec<u8>) -> Result<NamesFile, Error> {

        let l = validate_data_hash(&data)?;
        let l2 = validate_data_hmac(&encryption_key, &data, l)?;
        let (processor1, offset) = load_encryption_processor(alg1, encryption_key, &data)?;
        decrypt_data(processor1, &data, offset, l2);
        let mut entities: IdValueMap<HeaderEntity> = IdValueMap::new(processor2.clone());
        let offset2 = entities.load(&data, offset)?;
        let mut names: IdValueMap<String> = IdValueMap::new(processor2);
        let offset3 = names.load(&data, offset2)?;
        if offset3 != l2 {
            return Err(build_corrupted_data_error());
        }
        Ok(NamesFile{
            entities,
            names,
        })
    }

    pub fn save() {

    }
}

pub fn load_encryption_processor(alg1: u8, encryption_key: [u8; 32], data: &Vec<u8>) -> Result<(Arc<dyn CryptoProcessor>, usize), Error> {
    todo!()
}
