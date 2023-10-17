use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use crate::crypto::CryptoProcessor;
use crate::pman::id_value_map::id_value_map::{IdValueMapDataHandler, IdValueMapValue};
use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;

pub struct IdValueMapDataFileHandler {
    handler: IdValueMapLocalDataHandler
}

impl IdValueMapDataHandler for IdValueMapDataFileHandler {
    fn is_full(&self) -> bool {
        true
    }

    fn get_next_id(&self) -> u32 {
        self.handler.get_next_id()
    }

    fn get_map(&mut self) -> Result<HashMap<u32, Vec<u8>>, Error> {
        self.handler.get_map()
    }

    fn get(&self, id: u32) -> Result<Vec<u8>, Error> {
        self.handler.get(id)
    }

    fn mget(&self, ids: Vec<u32>) -> Result<HashMap<u32, Vec<u8>>, Error> {
        self.handler.mget(ids)
    }

    fn save(&self, next_id: u32, map: &HashMap<u32, Option<IdValueMapValue>>,
            processor: Arc<dyn CryptoProcessor>, new_processor: Arc<dyn CryptoProcessor>)
        -> Result<(HashMap<u32, Option<IdValueMapValue>>, Option<Vec<u8>>), Error> {
        self.handler.save(next_id, map, processor, new_processor)
    }
}