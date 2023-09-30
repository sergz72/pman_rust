use std::sync::Arc;
use crate::crypto::CryptoProcessor;
use crate::pman::header_entity::HeaderEntity;
use crate::pman::id_value_map::IdValueMap;

pub struct NamesFile {
    processor: Arc<dyn CryptoProcessor>,
    header: IdValueMap<Vec<u8>>,
    entities: IdValueMap<HeaderEntity>,
    names: IdValueMap<String>,
    passwords: IdValueMap<String>
}

impl NamesFile {
    pub fn new(processor1: Arc<dyn CryptoProcessor>, processor2: Arc<dyn CryptoProcessor>) -> NamesFile {
        NamesFile{processor: processor1.clone(),
            header: IdValueMap::new(processor1.clone()),
            entities: IdValueMap::new(processor1.clone()),
            names: IdValueMap::new(processor1),
            passwords: IdValueMap::new(processor2)}
    }
}