use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use uniffi::deps::bytes::BufMut;
use crate::crypto::CryptoProcessor;
use crate::error_builders::{build_corrupted_data_error, build_not_found_error};

pub trait ByteValue {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Self>, Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub struct IdValueMap {
    next_id: u32,
    map: HashMap<u32, Vec<u8>>,
    processor: Arc<dyn CryptoProcessor + Send + Sync>
}

impl IdValueMap {
    pub fn new(processor: Arc<dyn CryptoProcessor + Send + Sync>) -> Result<IdValueMap, Error> {
        Ok(IdValueMap { next_id: 100, map: HashMap::new(), processor })
    }

    pub fn load(source: &Vec<u8>, offset: usize, processor: Arc<dyn CryptoProcessor + Send + Sync>)
                -> Result<(IdValueMap, usize), Error> {
        let sl = source.len();
        if offset + 4 > sl {
            return Err(build_corrupted_data_error("IdValueMap.load1"));
        }
        // reading map length
        let mut buffer32 = [0u8; 4];
        let mut idx = offset;
        buffer32.copy_from_slice(&source[idx..idx + 4]);
        let mut l = u32::from_le_bytes(buffer32);
        idx += 4;
        let mut map = HashMap::new();
        let mut next_id = 100;
        while l > 0 {
            if idx + 8 > sl { // 4 for key + 4 for value length
                return Err(build_corrupted_data_error("IdValueMap.load2"));
            }
            //reading key
            buffer32.copy_from_slice(&source[idx..idx + 4]);
            idx += 4;
            let key = u32::from_le_bytes(buffer32);
            if map.contains_key(&key) {
                return Err(build_corrupted_data_error("IdValueMap.load3"));
            }
            // reading value length
            buffer32.copy_from_slice(&source[idx..idx + 4]);
            idx += 4;
            let value_length = u32::from_le_bytes(buffer32) as usize;
            if idx + value_length > sl {
                return Err(build_corrupted_data_error("IdValueMap.load4"));
            }
            // reading value
            let value = source[idx..idx + value_length].to_vec();
            idx += value_length;
            map.insert(key, value);
            if key >= next_id {
                next_id = key + 1;
            }
            l -= 1;
        }
        Ok((IdValueMap { next_id, map, processor }, idx))
    }

    pub fn add<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        let v = self.processor.encode(value.to_bytes())?;
        let id = self.next_id;
        self.map.insert(id, v);
        self.next_id += 1;
        Ok(id)
    }

    pub fn add_with_id<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if self.map.contains_key(&id) {
            return Err(Error::new(ErrorKind::InvalidInput, "record already exists"));
        }
        let v = self.processor.encode(value.to_bytes())?;
        self.map.insert(id, v);
        if id >= self.next_id {
            self.next_id = id + 1;
        }
        Ok(())
    }

    pub fn set<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        let v = self.processor.encode(value.to_bytes())?;
        self.map.insert(id, v);
        Ok(())
    }

    pub fn remove(&mut self, id: &u32) {
        let _ = self.map.remove(id);
    }

    pub fn get<T: ByteValue>(&self, id: u32) -> Result<T, Error> {
        if let Some(v) = self.map.get(&id) {
            let decoded = self.processor.decode(v)?;
            let value = T::from_bytes(decoded)?;
            Ok(*value)
        } else {
            Err(build_not_found_error())
        }
    }

    pub fn get_indirect<T: ByteValue>(&self, id: u32) -> Result<HashMap<u32, T>, Error> {
        let items: Vec<u32> = match self.get(id) {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    return Ok(HashMap::new());
                } else {
                    return Err(e);
                }
            }
        };
        if items.len() == 0 {
            return Ok(HashMap::new());
        }
        self.mget(items.into_iter().collect())
    }

    pub fn mget<T: ByteValue>(&self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        let mut result = HashMap::new();
        for id in ids {
            if let Some(v) = self.map.get(&id) {
                let decoded = self.processor.decode(v)?;
                let value = T::from_bytes(decoded)?;
                result.insert(id, *value);
            } else {
                return Err(build_not_found_error());
            }
        }
        Ok(result)
    }

    pub fn save(&mut self, output: &mut Vec<u8>,
                new_processor: Option<Arc<dyn CryptoProcessor + Send + Sync>>) -> Result<(), Error> {
        let encode_processor = new_processor.unwrap_or(self.processor.clone());
        output.put_u32_le(self.map.len() as u32);
        let mut new_map = HashMap::new();
        for (key, value) in &self.map {
            let k = *key;
            output.put_u32_le(k);
            let decoded = self.processor.decode(value)?;
            let encoded = encode_processor.encode(decoded)?;
            output.put_u32_le(encoded.len() as u32);
            output.put_slice(&encoded);
            new_map.insert(k, encoded);
        }
        self.map = new_map;
        self.processor = encode_processor;
        Ok(())
    }

    pub fn get_records_count(&self)  -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::AesProcessor;
    use crate::pman::id_value_map::id_value_map::IdValueMap;

    #[test]
    fn test_id_value_map() -> Result<(), Error> {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut map = IdValueMap::new(AesProcessor::new(key))?;
        let idx = map.add("test".to_string())?;
        map.set(idx, "test2".to_string())?;
        map.remove(&idx);
        let s2 = "test2".to_string();
        let s3 = "test3dmbfjsdhfgjsdgdfjsdgfjdsagfjsdgfjsguweyrtq  uieydhz`kjvbadfkulghewiurthkghfvkzjxviugrthiertfbdert".to_string();
        let idx2 = map.add(s2.clone())?;
        let idx3 = map.add(s3.clone())?;
        let mut v = Vec::new();
        map.save(&mut v, None)?;

        let (map2, end) = IdValueMap::load(&v, 0, AesProcessor::new(key))?;
        assert_eq!(end, v.len());
        assert_eq!(map2.map.len(), map.map.len());
        assert_eq!(map2.next_id, map.next_id);
        let v2: String = map2.get(idx2)?;
        assert_eq!(v2, s2);
        let v3: String = map2.get(idx3)?;
        assert_eq!(v3, s3);

        let vv: HashMap<u32, String> = map2.mget(HashSet::from([idx2, idx3]))?;
        assert_eq!(vv.len(), 2);
        let v22 = vv.get(&idx2);
        assert!(v22.is_some());
        assert_eq!(v22.unwrap().clone(), s2);
        let v23 = vv.get(&idx3);
        assert!(v23.is_some());
        assert_eq!(v23.unwrap().clone(), s3);

        let mut key2 = [0u8;32];
        OsRng.fill_bytes(&mut key2);
        let mut v2 = Vec::new();
        map.save(&mut v2, Some(AesProcessor::new(key2)))?;

        let (map3, end2) = IdValueMap::load(&v2, 0, AesProcessor::new(key2))?;
        assert_eq!(end2, v2.len());
        assert_eq!(map3.map.len(), map.map.len());
        assert_eq!(map3.next_id, map.next_id);
        let v22: String = map3.get(idx2)?;
        assert_eq!(v22, s2);
        let v23: String = map3.get(idx3)?;
        assert_eq!(v23, s3);

        Ok(())
    }
}