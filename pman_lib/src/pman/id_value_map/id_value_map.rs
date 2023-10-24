use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use crate::crypto::CryptoProcessor;

pub trait ByteValue {
    fn from_bytes(source: Vec<u8>) -> Result<Box<Self>, Error>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait IdValueMapDataHandler {
    fn is_full(&self) -> bool;
    fn get_next_id(&self) -> u32;
    fn get_map(&mut self) -> Result<HashMap<u32, Vec<u8>>, Error>;
    fn get(&self, id: u32) -> Result<Vec<u8>, Error>;
    fn mget(&self, ids: Vec<u32>) -> Result<HashMap<u32, Vec<u8>>, Error>;
    fn save(&self, next_id: u32, map: &HashMap<u32, Option<IdValueMapValue>>, processor: Arc<dyn CryptoProcessor>,
            new_processor: Arc<dyn CryptoProcessor>, alg1: Option<u8>, encryption_key: Option<[u8; 32]>)
        -> Result<(HashMap<u32, Option<IdValueMapValue>>, Option<Vec<u8>>), Error>;
}

pub struct IdValueMapValue {
    pub updated: bool,
    pub data: Vec<u8>
}

pub struct IdValueMap {
    next_id: u32,
    map: HashMap<u32, Option<IdValueMapValue>>,
    processor: Arc<dyn CryptoProcessor + Send + Sync>,
    other_handlers: Vec<Box<dyn IdValueMapDataHandler + Send + Sync>>,
    selected_handler: Box<dyn IdValueMapDataHandler + Send + Sync>
}

impl IdValueMap {
    pub fn new(processor: Arc<dyn CryptoProcessor + Send + Sync>, mut handlers: Vec<Box<dyn IdValueMapDataHandler + Send + Sync>>) -> Result<IdValueMap, Error> {
        let mut selected_handler = select_handler(&mut handlers)?;
        let map = selected_handler.get_map()?.into_iter()
            .map(|(k, v)|(k, Some(IdValueMapValue{ updated: false, data: v }))).collect();
        Ok(IdValueMap{next_id: selected_handler.get_next_id(), map, processor, other_handlers: handlers, selected_handler})
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
        let data = self.selected_handler.get(id)?;
        let decoded = self.processor.decode(&data)?;
        self.map.insert(id, Some(IdValueMapValue{ updated: false, data }));
        let value = T::from_bytes(decoded)?;
        Ok(*value)
    }

    pub fn get_indirect<T: ByteValue>(&mut self, id: u32) -> Result<HashMap<u32, T>, Error> {
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

    pub fn mget<T: ByteValue>(&mut self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        let mut result = HashMap::new();
        let mut missing_locally = Vec::new();
        for id in ids {
            if let Some(vv) = self.map.get(&id) {
                if let Some(v) = vv {
                    let decoded = self.processor.decode(&v.data)?;
                    let value = T::from_bytes(decoded)?;
                    result.insert(id, *value);
                } else {
                    return Err(Error::new(ErrorKind::NotFound, "deleted"))
                }
            } else {
                missing_locally.push(id);
            }
        }
        if !missing_locally.is_empty() {
            let data = self.selected_handler.mget(missing_locally)?;
            for (id, v) in data {
                let decoded = self.processor.decode(&v)?;
                self.map.insert(id, Some(IdValueMapValue { updated: false, data: v }));
                let value = T::from_bytes(decoded)?;
                result.insert(id, *value);
            }
        }
        Ok(result)
    }

    pub fn save(&mut self, new_processor: Option<Arc<dyn CryptoProcessor + Send + Sync>>, alg1: Option<u8>,
                encryption_key: Option<[u8; 32]>) -> Result<Option<Vec<u8>>, Error> {
        let encode_processor = new_processor.unwrap_or(self.processor.clone());
        let (map, mut output) =
            self.selected_handler.save(self.next_id, &self.map, self.processor.clone(),
                                       encode_processor.clone(), alg1, encryption_key)?;
        for handler in &self.other_handlers {
            let (_map, output2) = handler.save(self.next_id, &self.map,
                                               self.processor.clone(),
                                               encode_processor.clone(), alg1, encryption_key)?;
            if output.is_none() && output2.is_some() {
                output = output2;
            }
        }
        self.map = map;
        self.processor = encode_processor;
        Ok(output)
    }
}

fn select_handler(handlers: &mut Vec<Box<dyn IdValueMapDataHandler + Send + Sync>>) -> Result<Box<dyn IdValueMapDataHandler + Send + Sync>, Error> {
    match handlers.len() {
        0 => Err(Error::new(ErrorKind::InvalidData, "empty handlers list")),
        1 => Ok(handlers.remove(0)),
        _ => {
            for i in 0..handlers.len() {
                let h = &handlers[i];
                if h.is_full() {
                    return Ok(handlers.remove(i));
                }
            }
            Ok(handlers.remove(0))
        }
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
    use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;

    #[test]
    fn test_id_value_map() -> Result<(), Error> {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut map = IdValueMap::new(AesProcessor::new(key), vec![Box::new(IdValueMapLocalDataHandler::new())])?;
        let idx = map.add("test".to_string())?;
        map.set(idx, "test2".to_string())?;
        map.remove(idx);
        let s2 = "test2".to_string();
        let s3 = "test3dmbfjsdhfgjsdgdfjsdgfjdsagfjsdgfjsguweyrtq  uieydhz`kjvbadfkulghewiurthkghfvkzjxviugrthiertfbdert".to_string();
        let idx2 = map.add(s2.clone())?;
        let idx3 = map.add(s3.clone())?;
        let v = map.save(None, None, None)?.unwrap();

        let (handler, end) = IdValueMapLocalDataHandler::load(&v, 0)?;
        assert_eq!(end, v.len());
        let mut map2 = IdValueMap::new(AesProcessor::new(key), vec![Box::new(handler)])?;
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
        let v2 = map.save(Some(AesProcessor::new(key2)), None, None)?.unwrap();

        let (handler2, end2) = IdValueMapLocalDataHandler::load(&v2, 0)?;
        assert_eq!(end2, v2.len());
        let mut map3 = IdValueMap::new(AesProcessor::new(key2), vec![Box::new(handler2)])?;
        assert_eq!(map3.map.len(), map.map.len());
        assert_eq!(map3.next_id, map.next_id);
        let v22: String = map3.get(idx2)?;
        assert_eq!(v22, s2);
        let v23: String = map3.get(idx3)?;
        assert_eq!(v23, s3);

        Ok(())
    }
}