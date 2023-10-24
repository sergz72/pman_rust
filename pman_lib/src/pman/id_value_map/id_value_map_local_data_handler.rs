use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use uniffi::deps::bytes::BufMut;
use crate::crypto::CryptoProcessor;
use crate::error_builders::{build_corrupted_data_error, build_not_found_error};
use crate::pman::id_value_map::id_value_map::{IdValueMapDataHandler, IdValueMapValue};

pub struct IdValueMapLocalDataHandler {
    next_id: u32,
    map: Option<HashMap<u32, Vec<u8>>>,
}

impl IdValueMapDataHandler for IdValueMapLocalDataHandler {
    fn is_full(&self) -> bool {
        true
    }
    fn get_next_id(&self) -> u32 {
        self.next_id
    }

    fn get_map(&mut self) -> Result<HashMap<u32, Vec<u8>>, Error> {
        self.map.take().ok_or(Error::new(ErrorKind::NotFound, "map is None"))
    }

    fn get(&self, _id: u32) -> Result<Vec<u8>, Error> {
        Err(build_not_found_error())
    }

    fn mget(&self, _ids: Vec<u32>) -> Result<HashMap<u32, Vec<u8>>, Error> {
        Err(build_not_found_error())
    }

    fn save(&self, _next_id: u32, map: &HashMap<u32, Option<IdValueMapValue>>, processor: Arc<dyn CryptoProcessor>,
            new_processor: Arc<dyn CryptoProcessor>, _alg1: Option<u8>, _encryption_key: Option<[u8; 32]>)
        -> Result<(HashMap<u32, Option<IdValueMapValue>>, Option<Vec<u8>>), Error> {
        let mut output = Vec::new();
        output.put_u32_le(map.values().filter(|v|v.is_some()).count() as u32);
        let mut new_map = HashMap::new();
        for (key, value_opt) in map {
            if let Some(value) = value_opt {
                output.put_u32_le(*key);
                let decoded = processor.decode(&value.data)?;
                let encoded = new_processor.encode(decoded)?;
                output.put_u32_le(encoded.len() as u32);
                output.put_slice(&encoded);
                new_map.insert(*key, Some(IdValueMapValue { updated: false, data: encoded }));
            }
        }
        Ok((new_map, Some(output)))
    }
}

impl IdValueMapLocalDataHandler {
    pub fn new() -> IdValueMapLocalDataHandler {
        IdValueMapLocalDataHandler{ next_id: 100, map: Some(HashMap::new()) }
    }

    pub fn load(source: &Vec<u8>, offset: usize) -> Result<(IdValueMapLocalDataHandler, usize), Error> {
        let sl = source.len();
        if offset + 4 > sl {
            return Err(build_corrupted_data_error());
        }
        // reading map length
        let mut buffer32 = [0u8; 4];
        let mut idx = offset;
        buffer32.copy_from_slice(&source[idx..idx + 4]);
        let mut l = u32::from_le_bytes(buffer32);
        idx += 4;
        let mut map = HashMap::new();
        let mut next_id = 1;
        while l > 0 {
            if idx + 8 > sl { // 4 for key + 4 for value length
                return Err(build_corrupted_data_error());
            }
            //reading key
            buffer32.copy_from_slice(&source[idx..idx + 4]);
            idx += 4;
            let key = u32::from_le_bytes(buffer32);
            if map.contains_key(&key) {
                return Err(build_corrupted_data_error());
            }
            // reading value length
            buffer32.copy_from_slice(&source[idx..idx + 4]);
            idx += 4;
            let value_length = u32::from_le_bytes(buffer32) as usize;
            if idx + value_length > sl {
                return Err(build_corrupted_data_error());
            }
            // reading value
            let value = source[idx..idx+value_length].to_vec();
            idx += value_length;
            map.insert(key, value);
            if key >= next_id {
                next_id = key + 1;
            }
            l -= 1;
        }
        Ok((IdValueMapLocalDataHandler{ next_id, map: Some(map) }, idx))
    }
}
