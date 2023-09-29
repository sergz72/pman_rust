use crate::crypto::CryptoProcessor;
use crate::pman::id_value_map::IdValueMap;

pub struct NamesFile {
    names: IdValueMap<String>
}

impl NamesFile {
    pub fn new(processor: Box<dyn CryptoProcessor>) -> NamesFile {
        NamesFile{names: IdValueMap::new(processor)}
    }
}