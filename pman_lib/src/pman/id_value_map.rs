use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use uniffi::deps::bytes::BufMut;
use crate::crypto::{build_corrupted_data_error, build_unsupported_error, CryptoProcessor};

pub trait ByteValue {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Self>, Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

impl ByteValue for Vec<u8> {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Vec<u8>>, Error> {
        Ok(Box::new(source))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
}

impl ByteValue for String {
    fn from_bytes(source: Vec<u8>) -> Result<Box<String>, Error> {
        String::from_utf8(source)
            .map(|v|Box::new(v))
            .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

pub trait IdValueMapDataHandler {
    fn get_next_id(&self) -> u32;
    fn get_map(&self) -> Result<HashMap<u32, Vec<u8>>, Error>;
    fn get(&self, id: u32) -> Result<Vec<u8>, Error>;
    fn exists(&self, id: u32) -> Result<bool, Error>;
    fn save(&self, map: &mut IdValueMap, new_processor: Option<Arc<dyn CryptoProcessor>>) -> Result<Option<Vec<u8>>, Error>;
}

pub struct IdValueMapLocalDataHandler {
    next_id: u32,
    map: Option<HashMap<u32, Vec<u8>>>,
}

impl IdValueMapDataHandler for IdValueMapLocalDataHandler {
    fn get_next_id(&self) -> u32 {
        self.next_id
    }

    fn get_map(&self) -> Result<HashMap<u32, Vec<u8>>, Error> {
        self.map.ok_or(Error::new(ErrorKind::NotFound, "map is None"))
    }

    fn get(&self, id: u32) -> Result<Vec<u8>, Error> {
        Err(build_unsupported_error())
    }

    fn exists(&self, id: u32) -> Result<bool, Error> {
        Ok(false)
    }

    fn save(&self, map: &mut IdValueMap, new_processor: Option<Arc<dyn CryptoProcessor>>) -> Result<Option<Vec<u8>>, Error> {
        let encode_processor = new_processor.unwrap_or(map.processor.clone());
        let mut output = Vec::new();
        output.put_u32_le(map.map.len() as u32);
        let mut new_map = HashMap::new();
        for (key, value) in &map.map {
            output.put_u32_le(*key);
            let decoded = map.processor.decode(&value.data)?;
            let encoded = encode_processor.encode(decoded)?;
            output.put_u32_le(encoded.len() as u32);
            output.put_slice(&encoded);
            new_map.insert(*key, IdValueMapValue{updated: false, data: encoded});
        }
        map.map = new_map;
        map.processor = encode_processor;
        Ok(Some(output))
    }
}

impl IdValueMapLocalDataHandler {
    pub fn new() -> IdValueMapLocalDataHandler {
        IdValueMapLocalDataHandler{ next_id: 1, map: Some(HashMap::new()) }
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

struct IdValueMapValue {
    updated: bool,
    data: Vec<u8>
}

pub struct IdValueMap {
    next_id: u32,
    map: HashMap<u32, IdValueMapValue>,
    processor: Arc<dyn CryptoProcessor>,
    handler: Box<dyn IdValueMapDataHandler>
}

impl IdValueMap {
    pub fn new(processor: Arc<dyn CryptoProcessor>, handler: Box<dyn IdValueMapDataHandler>) -> Result<IdValueMap, Error> {
        let map = handler.get_map()?.into_iter()
            .map(|(k, v)|(k, IdValueMapValue{ updated: false, data: v })).collect();
        Ok(IdValueMap{next_id: handler.get_next_id(), map, processor, handler})
    }

    pub fn add<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        let v = self.processor.encode(value.to_bytes())?;
        let id = self.next_id;
        self.map.insert(id, IdValueMapValue{updated: true, data: v});
        self.next_id += 1;
        Ok(id)
    }

    pub fn add_with_id<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if self.map.contains_key(&id) {
            return Err(Error::new(ErrorKind::InvalidInput, "record already exists"));
        }
        let v = self.processor.encode(value.to_bytes())?;
        self.map.insert(id, IdValueMapValue{updated: true, data: v});
        if id >= self.next_id {
            self.next_id = id + 1;
        }
        Ok(())
    }

    pub fn set<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        self.exists(id)?;
        let v = self.processor.encode(value.to_bytes())?;
        self.map.insert(id, IdValueMapValue{updated: true, data: v});
        Ok(())
    }

    pub fn remove(&mut self, id: u32) -> Result<(), Error> {
        self.exists(id)?;
        self.map.remove(&id);
        Ok(())
    }

    fn exists(&self, id: u32) -> Result<(), Error> {
        if !self.map.contains_key(&id) {
            return Err(Error::new(ErrorKind::InvalidInput, "not found"));
        }
        Ok(())
    }

    pub fn get<T: ByteValue>(&self, id: u32) -> Result<T, Error> {
        self.exists(id)?;
        let v = self.map.get(&id).unwrap();
        let decoded = self.processor.decode(&v.data)?;
        let value = T::from_bytes(decoded)?;
        Ok(*value)
    }

    pub fn save(&mut self, new_processor: Option<Arc<dyn CryptoProcessor>>) -> Result<Option<Vec<u8>>, Error> {
        self.handler.save(&mut self, new_processor)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::AesProcessor;
    use crate::pman::id_value_map::{IdValueMap, IdValueMapLocalDataHandler};

    #[test]
    fn test_id_name_map() -> Result<(), Error> {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut map = IdValueMap::new(AesProcessor::new(key), Box::new(IdValueMapLocalDataHandler::new()))?;
        let idx = map.add("test".to_string())?;
        map.set(idx, "test2".to_string())?;
        map.remove(idx)?;
        let s2 = "test2".to_string();
        let s3 = "test3dmbfjsdhfgjsdgdfjsdgfjdsagfjsdgfjsguweyrtq  uieydhz`kjvbadfkulghewiurthkghfvkzjxviugrthiertfbdert".to_string();
        let idx2 = map.add(s2.clone())?;
        let idx3 = map.add(s3.clone())?;
        let v = map.save(None)?.unwrap();

        let (handler, end) = IdValueMapLocalDataHandler::load(&v, 0)?;
        assert_eq!(end, v.len());
        let mut map2 = IdValueMap::new(AesProcessor::new(key), Box::new(handler))?;
        assert_eq!(map2.map.len(), map.map.len());
        assert_eq!(map2.next_id, map.next_id);
        let v2: String = map2.get(idx2)?;
        assert_eq!(v2, s2);
        let v3: String = map2.get(idx3)?;
        assert_eq!(v3, s3);

        let mut key2 = [0u8;32];
        OsRng.fill_bytes(&mut key2);
        let v2 = map.save(Some(AesProcessor::new(key2)))?.unwrap();

        let (handler2, end2) = IdValueMapLocalDataHandler::load(&v2, 0)?;
        assert_eq!(end2, v2.len());
        let mut map3 = IdValueMap::new(AesProcessor::new(key2), Box::new(handler2))?;
        assert_eq!(map3.map.len(), map.map.len());
        assert_eq!(map3.next_id, map.next_id);
        let v22: String = map3.get(idx2)?;
        assert_eq!(v22, s2);
        let v23: String = map3.get(idx3)?;
        assert_eq!(v23, s3);

        Ok(())
    }
}