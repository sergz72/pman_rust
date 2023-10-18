use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use crate::crypto::{build_corrupted_data_error, CryptoProcessor};
use crate::pman::id_value_map::id_value_map::{IdValueMapDataHandler, IdValueMapValue};
use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;
use crate::pman::pman_database_file::{build_aes_processor, build_chacha_processor, build_chacha_salt, decrypt_data, default_chacha_properties, validate_data_hash, validate_data_hmac};

pub struct IdValueMapDataFileHandler {
    handler: IdValueMapLocalDataHandler
}

impl IdValueMapDataHandler for IdValueMapDataFileHandler {
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
            encryption_key: Option<[u8; 32]>)
        -> Result<(HashMap<u32, Option<IdValueMapValue>>, Option<Vec<u8>>), Error> {
        let (map, data_option) =
            self.handler.save(next_id, map, processor, new_processor, None, None)?;
        let data = data_option.unwrap();
        // encrypting data
        let alg11 = Vec::new();
        let processor11 = build_encryption_processor(alg11, encryption_key)?;
        let encrypted = data;
        Ok((map, Some(encrypted)))
    }
}

impl IdValueMapDataFileHandler {
    pub fn new() -> IdValueMapDataFileHandler {
        IdValueMapDataFileHandler { handler: IdValueMapLocalDataHandler::new() }
    }

    pub fn load(mut data: Vec<u8>, encryption_key: [u8; 32], alg1: u8) -> Result<IdValueMapDataFileHandler, Error> {
        // decrypting data
        let l = validate_data_hash(&data)?;
        let l2 = validate_data_hmac(&encryption_key, &data, l)?;
        let (processor1, offset) = load_encryption_processor(alg1, encryption_key, &data)?;
        decrypt_data(processor1, &mut data, offset, l2)?;
        let (handler, offset2) = IdValueMapLocalDataHandler::load(&data, offset)?;
        if offset2 != l2 {
            return Err(build_corrupted_data_error());
        }
        Ok(IdValueMapDataFileHandler { handler })
    }
}

fn load_encryption_processor(alg1: u8, encryption_key: [u8; 32], data: &Vec<u8>) -> Result<(Arc<dyn CryptoProcessor>, usize), Error> {
    todo!()
}

fn build_encryption_processor(algorithm: u8, encryption_key: [u8; 32]) -> Result<(Arc<dyn CryptoProcessor>, Vec<u8>), Error> {
    let mut algorithm_parameters = vec![algorithm];
    match algorithm {
        ENCRYPTION_ALGORITHM_AES => {
            let processor = build_aes_processor(algorithm_parameters, encryption_key)?;
            Ok((processor, Vec::new()))
        },
        ENCRYPTION_ALGORITHM_CHACHA20 => {
            let salt = build_chacha_salt();
            algorithm_parameters.extend_from_slice(&salt);
            let processor = build_chacha_processor(algorithm_parameters, encryption_key)?;
            Ok((processor, Vec::from(salt)))
        },
        _ => Err(Error::new(ErrorKind::Unsupported, "unsupported encryption algorithm"))
    }
}
