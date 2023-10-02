use std::io::Error;
use std::sync::Arc;
use crate::crypto::{CryptoProcessor, NoEncryptionProcessor};
use crate::pman::header_entity::HeaderEntity;
use crate::pman::id_value_map::IdValueMap;
use crate::pman::passwords_file::PasswordsFile;
use crate::pman::pman_database_file::{build_encryption_key, decrypt_data, get_encryption_algorithms, validate_data_hash, validate_data_hmac};

pub struct NamesFile {
    processor: Arc<dyn CryptoProcessor>,
    header: IdValueMap<Vec<u8>>,
    entities: IdValueMap<HeaderEntity>,
    names: IdValueMap<String>
}

impl NamesFile {
    pub fn new(processor: Arc<dyn CryptoProcessor>) -> NamesFile {
        NamesFile{processor: processor.clone(),
            header: IdValueMap::new(processor.clone()),
            entities: IdValueMap::new(processor.clone()),
            names: IdValueMap::new(processor)}
    }

    pub fn load(algorithm_parameters: Vec<u8>, encryption_key: [u8; 32],
                password2_hash: Vec<u8>, data: Vec<u8>, offset: usize, length: usize) -> Result<(NamesFile, PasswordsFile), Error> {
        let l = validate_data_hash(&data, offset, length)?;
        let mut h: IdValueMap<Vec<u8>> = IdValueMap::new(NoEncryptionProcessor::new());
        let offset2 = h.load(&data, offset)?;
        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let encryption_key2 = build_encryption_key(&h, &password2_hash)?;
        let l2 = validate_data_hmac(&encryption_key, &data, offset2, l)?;
        decrypt_data(alg1, &encryption_key2, &data, offset2, l2);
        let mut entities: IdValueMap<HeaderEntity> = IdValueMap::new(NoEncryptionProcessor::new());
        let offset3 = entities.load(&data, offset2)?;
        let encryption_processor = build_encryption_processor(algorithm_parameters, encryption_key)?;
        let mut names: IdValueMap<String> = IdValueMap::new(encryption_processor);
        let offset4 = names.load(&data, offset3)?;
        let passwords_file = PasswordsFile::load(alg2, encryption_key2, data, offset4, l2)?;
        Ok((NamesFile{
            processor: Arc::new(()),
            header: h,
            entities,
            names,
        }, passwords_file))
    }

    pub fn save() {

    }
}

fn build_encryption_processor(algorithm_parameters: Vec<u8>, encryption_key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor>, Error> {
    todo!()
}