use std::io::Error;
use std::sync::Arc;
use crate::crypto::CryptoProcessor;
use crate::pman::header_entity::HeaderEntity;
use crate::pman::id_value_map::IdValueMap;
use crate::pman::pman_database_file::validate_data_hash;

pub struct NamesFile {
    header: IdValueMap<Vec<u8>>,
    entities: IdValueMap<HeaderEntity>,
    names: IdValueMap<String>
}

impl NamesFile {
    pub fn new(processor2: Arc<dyn CryptoProcessor>) -> NamesFile {
        NamesFile{header: IdValueMap::new(processor2.clone()),
            entities: IdValueMap::new(processor2.clone()),
            names: IdValueMap::new(processor2)}
    }

    pub fn load(processor1: Arc<dyn CryptoProcessor>, processor2: Arc<dyn CryptoProcessor>,
                data: Vec<u8>) -> Result<NamesFile, Error> {

        let l = validate_data_hash(&data)?;
        let mut h: IdValueMap<Vec<u8>> = IdValueMap::new(processor2.clone());
        let offset = h.load(&data, 0)?;
        let mut entities: IdValueMap<HeaderEntity> = IdValueMap::new(processor2.clone());
        let offset2 = entities.load(&data, offset)?;
        let mut names: IdValueMap<String> = IdValueMap::new(processor2);
        let offset3 = names.load(&data, offset2)?;
        Ok(NamesFile{
            header: h,
            entities,
            names,
        })
    }

    pub fn save() {

    }
}
