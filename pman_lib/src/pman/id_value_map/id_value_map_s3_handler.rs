use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, Read};
use std::sync::Arc;
use s3cli_lib::{build_key_info, KeyInfo};
use crate::crypto::CryptoProcessor;
use crate::pman::id_value_map::id_value_map::{IdValueMapDataHandler, IdValueMapValue};
use crate::pman::id_value_map::id_value_map_data_file_handler::IdValueMapDataFileHandler;

pub struct IdValueMapS3Handler {
    key_info: KeyInfo,
    path: String,
    handler: IdValueMapDataFileHandler
}

impl IdValueMapDataHandler for IdValueMapS3Handler {
    fn is_full(&self) -> bool {
        self.handler.is_full()
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
            processor: Arc<dyn CryptoProcessor>, new_processor: Arc<dyn CryptoProcessor>, alg1: Option<u8>,
            encryption_key_option: Option<[u8; 32]>)
            -> Result<(HashMap<u32, Option<IdValueMapValue>>, Option<Vec<u8>>), Error> {
        let (map, data) =
            self.handler.save(next_id, map, processor, new_processor, alg1, encryption_key_option)?;
        self.save_to_s3(data.unwrap())?;
        Ok((map, None))
    }
}

impl IdValueMapS3Handler {
    fn save_to_s3(&self, data: Vec<u8>) -> Result<(), Error> {
        let request_info = self.key_info.build_request_info("PUT",
                                                       chrono::Utc::now(), &Vec::new(),
                                                            &self.path)?;
        let _ = request_info.make_request(Some(data))?;
        Ok(())
    }

    pub fn new(location_data: Vec<u8>) -> Result<IdValueMapS3Handler, Error> {
        let path = ???;
        let key_info = build_key_info(location_data)?;
        Ok(IdValueMapS3Handler { key_info, path, handler: IdValueMapDataFileHandler::new() })
    }

    pub fn load(location_data: Vec<u8>, encryption_key: [u8; 32], alg1: u8) -> Result<IdValueMapS3Handler, Error> {
        let path = ???;
        let key_info = build_key_info(location_data)?;
        let data = load_from_s3(&key_info, &path)?;
        let handler =
            IdValueMapDataFileHandler::load(data, encryption_key, alg1)?;
        Ok(IdValueMapS3Handler { key_info, path, handler })
    }
}

fn load_from_s3(key_info: &KeyInfo, path: &String) -> Result<Vec<u8>, Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(), &Vec::new(), path)?;
    request_info.make_request(None)
}