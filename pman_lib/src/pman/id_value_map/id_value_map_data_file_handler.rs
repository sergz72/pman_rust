use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use crate::crypto::{AesProcessor, ChachaProcessor, CryptoProcessor};
use crate::error_builders::build_corrupted_data_error;
use crate::pman::id_value_map::id_value_map::{IdValueMapDataHandler, IdValueMapValue};
use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;
use crate::pman::pman_database_file::{add_data_hash_and_hmac, build_aes_processor, build_chacha_processor,
                                      build_chacha_salt, build_unsupported_algorithm_error, decrypt_data,
                                      validate_data_hash, validate_data_hmac, ENCRYPTION_ALGORITHM_AES,
                                      ENCRYPTION_ALGORITHM_CHACHA20};

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
            encryption_key_option: Option<[u8; 32]>)
        -> Result<(HashMap<u32, Option<IdValueMapValue>>, Option<Vec<u8>>), Error> {
        if alg1.is_none() || encryption_key_option.is_none() {
            return Err(Error::new(ErrorKind::InvalidInput, "alg1 & encryption_key should be provided"));
        }
        let (map, data_option) =
            self.handler.save(next_id, map, processor, new_processor, None, None)?;
        let mut data = data_option.unwrap();
        // encrypting data
        let encryption_key = encryption_key_option.unwrap();
        let (processor11, mut out_data)
            = build_encryption_processor(alg1.unwrap(), encryption_key)?;
        processor11.encode_bytes(&mut data)?;
        out_data.extend_from_slice(&data);
        add_data_hash_and_hmac(&mut out_data, encryption_key)?;
        Ok((map, Some(out_data)))
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
            return Err(build_corrupted_data_error("IdValueMapDataFileHandler.load"));
        }
        Ok(IdValueMapDataFileHandler { handler })
    }
}

fn load_encryption_processor(alg1: u8, encryption_key: [u8; 32], data: &Vec<u8>) -> Result<(Arc<dyn CryptoProcessor>, usize), Error> {
    match alg1 {
        ENCRYPTION_ALGORITHM_AES=> Ok((AesProcessor::new(encryption_key), 0)),
        ENCRYPTION_ALGORITHM_CHACHA20 => {
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&data[0..12]);
            Ok((ChachaProcessor::new(encryption_key, iv), 12))
        },
        _ => Err(build_unsupported_algorithm_error())
    }
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
        _ => Err(build_unsupported_algorithm_error())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::AesProcessor;
    use crate::pman::id_value_map::id_value_map::{IdValueMapDataHandler, IdValueMapValue};
    use crate::pman::id_value_map::id_value_map_data_file_handler::IdValueMapDataFileHandler;
    use crate::pman::pman_database_file::{build_argon2_salt, build_chacha_salt, ENCRYPTION_ALGORITHM_CHACHA20};

    #[test]
    fn test_handler() -> Result<(), Error> {
        let mut encryption_key = [0u8; 32];
        OsRng.fill_bytes(&mut encryption_key);
        let processor= AesProcessor::new(encryption_key);
        let d1 = Vec::from(build_chacha_salt());
        let data1 = processor.encode(d1.clone())?;
        let d2 = Vec::from(build_argon2_salt());
        let data2 = processor.encode(d2.clone())?;
        let map: HashMap<u32, Option<IdValueMapValue>> = HashMap::from([
            (1, Some(IdValueMapValue{ updated: false, data: data1})),
            (2, Some(IdValueMapValue{ updated: false, data: data2}))
        ]);
        let handler = IdValueMapDataFileHandler::new();
        let (_map, data_option) = handler.save(3, &map,
                                               processor.clone(), processor.clone(),
                                               Some(ENCRYPTION_ALGORITHM_CHACHA20),
                                               Some(encryption_key))?;
        let mut handler2 =
            IdValueMapDataFileHandler::load(data_option.unwrap(), encryption_key,
                                            ENCRYPTION_ALGORITHM_CHACHA20)?;
        assert_eq!(handler2.get_next_id(), 3);
        let map = handler2.get_map()?;
        assert_eq!(map.len(), 2);
        let item1 = map.get(&1).unwrap();
        let d11 = processor.decode(item1)?;
        assert_eq!(d11, d1);
        let item2 = map.get(&2).unwrap();
        let d12 = processor.decode(item2)?;
        assert_eq!(d12, d2);
        Ok(())
    }
}