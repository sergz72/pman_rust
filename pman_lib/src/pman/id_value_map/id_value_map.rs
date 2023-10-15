use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use uniffi::deps::bytes::BufMut;
use crate::crypto::{build_corrupted_data_error, build_unsupported_error, CryptoProcessor};

pub trait ByteValue {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Self>, Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait IdValueMapDataHandler {
    fn get_next_id(&self) -> u32;
    fn get_map(&mut self) -> Result<HashMap<u32, Vec<u8>>, Error>;
    fn get(&self, id: u32) -> Result<Vec<u8>, Error>;
    fn save(&self, next_id: u32, map: &HashMap<u32, Option<IdValueMapValue>>, processor: Arc<dyn CryptoProcessor>,
            new_processor: Arc<dyn CryptoProcessor>) -> Result<(HashMap<u32, Option<IdValueMapValue>>, Option<Vec<u8>>), Error>;
}

pub struct IdValueMapValue {
    pub updated: bool,
    pub data: Vec<u8>
}

pub struct IdValueMap {
    next_id: u32,
    map: HashMap<u32, Option<IdValueMapValue>>,
    processor: Arc<dyn CryptoProcessor>,
    handler: Box<dyn IdValueMapDataHandler>
}

impl IdValueMap {
    pub fn new(processor: Arc<dyn CryptoProcessor>, mut handler: Box<dyn IdValueMapDataHandler>) -> Result<IdValueMap, Error> {
        let map = handler.get_map()?.into_iter()
            .map(|(k, v)|(k, Some(IdValueMapValue{ updated: false, data: v }))).collect();
        Ok(IdValueMap{next_id: handler.get_next_id(), map, processor, handler})
    }

    pub fn add<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        let v = self.processor.encode(value.to_bytes())?;
        let id = self.next_id;
        self.map.insert(id, Some(IdValueMapValue{updated: true, data: v}));
        self.next_id += 1;
        Ok(id)
    }

    pub fn add_with_id<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if self.map.contains_key(&id) {
            return Err(Error::new(ErrorKind::InvalidInput, "record already exists"));
        }
        let v = self.processor.encode(value.to_bytes())?;
        self.map.insert(id, Some(IdValueMapValue{updated: true, data: v}));
        if id >= self.next_id {
            self.next_id = id + 1;
        }
        Ok(())
    }

    pub fn set<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        let v = self.processor.encode(value.to_bytes())?;
        self.map.insert(id, Some(IdValueMapValue{updated: true, data: v}));
        Ok(())
    }

    pub fn remove(&mut self, id: u32) {
        self.map.insert(id, None);
    }

    pub fn get<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        if let Some(vv) = self.map.get(&id) {
            if let Some(v) = vv {
                let decoded = self.processor.decode(&v.data)?;
                let value = T::from_bytes(decoded)?;
                return Ok(*value);
            } else {
                return Err(Error::new(ErrorKind::NotFound, "deleted"))
            }
        }
        let data = self.handler.get(id)?;
        let decoded = self.processor.decode(&data)?;
        self.map.insert(id, Some(IdValueMapValue{ updated: false, data }));
        let value = T::from_bytes(decoded)?;
        Ok(*value)
    }

    pub fn save(&mut self, new_processor: Option<Arc<dyn CryptoProcessor>>) -> Result<Option<Vec<u8>>, Error> {
        let encode_processor = new_processor.unwrap_or(self.processor.clone());
        let (map, output) =
            self.handler.save(self.next_id, &self.map, self.processor.clone(), encode_processor.clone())?;
        self.map = map;
        self.processor = encode_processor;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::AesProcessor;
    use crate::pman::id_value_map::id_value_map::IdValueMap;
    use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;

    #[test]
    fn test_id_name_map() -> Result<(), Error> {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut map = IdValueMap::new(AesProcessor::new(key), Box::new(IdValueMapLocalDataHandler::new()))?;
        let idx = map.add("test".to_string())?;
        map.set(idx, "test2".to_string())?;
        map.remove(idx);
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