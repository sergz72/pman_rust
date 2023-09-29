use crate::crypto::NoEncryptionProcessor;
use crate::pman::id_value_map::IdValueMap;

pub struct EntityMap {
    map: IdValueMap
}

impl EntityMap {
    pub fn new() -> EntityMap {
        EntityMap{map: IdValueMap::new(NoEncryptionProcessor::new())}
    }
}