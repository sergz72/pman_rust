use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use crate::crypto::{AesProcessor, ChachaProcessor, CryptoProcessor};
use crate::error_builders::{build_corrupted_data_error, build_unsupported_algorithm_error};
use crate::pman::id_value_map::id_value_map::{ByteValue, IdValueMap};
use crate::pman::ids::{ENCRYPTION_ALGORITHM1_PROPERTIES_ID, ENCRYPTION_ALGORITHM2_PROPERTIES_ID,
                       FILE_LOCATION_ID, HASH_ALGORITHM_PROPERTIES_ID};
use crate::pman::pman_database_file::{build_aes_processor, build_chacha_processor, build_chacha_salt, build_encryption_keys, default_aes_properties, default_argon2_properties, default_chacha_properties, ENCRYPTION_ALGORITHM_AES, ENCRYPTION_ALGORITHM_CHACHA20, FILE_LOCATION_QS3, get_encryption_algorithms, modify_header_algorithm_properties, set_argon2_in_header, set_file_location_qs3};

pub struct DataFile {
    is_updated: bool,
    names_data: IdValueMap,
    passwords_data: Option<IdValueMap>,
    data_length: usize,
    passwords_data_offset: usize
}

pub trait DataFileHandler {
    fn save(&self, data: Vec<u8>) -> Result<(), Error>;
}

type HmacSha256 = Hmac<Sha256>;

impl DataFile {
    pub fn new(names_data: IdValueMap, processor22: Arc<dyn CryptoProcessor + Send + Sync>)
        -> Result<DataFile, Error> {
        Ok(DataFile {is_updated: true, names_data,
            passwords_data: Some(IdValueMap::new(processor22)?), data_length: 0,
            passwords_data_offset: 0})
    }

    pub fn pre_load(data: &mut Vec<u8>, offset: usize, l: usize, encryption_key1: [u8; 32], alg11: u8,
                    processor12: Arc<dyn CryptoProcessor + Send + Sync>,) -> Result<DataFile, Error> {
        let data_length = validate_data_hmac(&encryption_key1, data, l)?;

        // decrypting names data
        let (processor1, offset2) =
            load_encryption_processor(alg11, encryption_key1, data, offset)?;
        decrypt_data(processor1, data, offset2, data_length)?;
        let (names_data, passwords_data_offset) =
            IdValueMap::load(data, offset2, processor12)?;

        Ok(DataFile {is_updated: false, names_data, passwords_data: None, data_length, passwords_data_offset})
    }

    pub fn load(&mut self, data: &mut Vec<u8>, encryption_key2: [u8; 32], alg21: u8,
                processor22: Arc<dyn CryptoProcessor + Send + Sync>) -> Result<(), Error> {
        if self.passwords_data.is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "passwords data already loaded"));
        }
        if self.data_length == 0 || self.passwords_data_offset == 0 {
            return Err(Error::new(ErrorKind::InvalidData, "zero offsets"));
        }
        // decrypting passwords data
        let (processor2, offset) =
            load_encryption_processor(alg21, encryption_key2, data,
                                      self.passwords_data_offset)?;
        decrypt_data(processor2, data, offset, self.data_length)?;
        let (passwords_data, offset2) =
            IdValueMap::load(&data, offset, processor22)?;
        if offset2 != self.data_length {
            return Err(build_corrupted_data_error("DataFile.load"));
        }
        self.passwords_data = Some(passwords_data);
        Ok(())
    }

    pub fn set_updated(&mut self) {
        self.is_updated = true;
    }

    fn check_passwords_data(&self) -> Result<(), Error> {
        if self.passwords_data.is_none() {
            return Err(Error::new(ErrorKind::NotFound, "passwords data is none"));
        }
        Ok(())
    }

    pub fn save(&mut self, data: &mut Vec<u8>, encryption_key1: [u8; 32], alg11: u8,
                processor12: Option<Arc<dyn CryptoProcessor + Send + Sync>>,
                encryption_key2: [u8; 32], alg21: u8,
                processor22: Option<Arc<dyn CryptoProcessor + Send + Sync>>) -> Result<(), Error> {
        self.check_passwords_data()?;
        let processor11
            = build_encryption_processor(alg11, encryption_key1, data)?;
        let offset = data.len();
        self.names_data.save(data,processor12)?;
        let processor21
            = build_encryption_processor(alg21, encryption_key2, data)?;
        let offset2 = data.len();
        self.passwords_data.as_mut().unwrap().save(data,processor22)?;
        let offset3 = data.len();

        // encrypt passwords info
        encrypt_data(processor21, data, offset2, offset3)?;
        // encrypt names+passwords info
        encrypt_data(processor11, data, offset, offset3)?;

        add_data_hash_and_hmac(data, encryption_key1)
    }

    pub fn get_from_names<T: ByteValue>(&self, id: u32) -> Result<T, Error> {
        self.names_data.get(id)
    }

    pub fn get_from_passwords<T: ByteValue>(&self, id: u32) -> Result<T, Error> {
        self.check_passwords_data()?;
        self.passwords_data.as_ref().unwrap().get(id)
    }

    pub fn mget_from_names<T: ByteValue>(&self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        self.names_data.mget(ids)
    }

    pub fn mget_from_passwords<T: ByteValue>(&self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        self.check_passwords_data()?;
        self.passwords_data.as_ref().unwrap().mget(ids)
    }

    pub fn get_indirect_from_names<T: ByteValue>(&self, id: u32) -> Result<HashMap<u32, T>, Error> {
        self.names_data.get_indirect(id)
    }

    pub fn get_indirect_from_passwords<T: ByteValue>(&self, id: u32) -> Result<HashMap<u32, T>, Error> {
        self.check_passwords_data()?;
        self.passwords_data.as_ref().unwrap().get_indirect(id)
    }

    pub fn add_to_names<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        self.is_updated = true;
        self.names_data.add(value)
    }

    pub fn add_to_passwords<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        self.check_passwords_data()?;
        self.is_updated = true;
        self.passwords_data.as_mut().unwrap().add(value)
    }

    pub fn set_in_names<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        self.is_updated = true;
        self.names_data.set(id, value)
    }

    pub fn set_in_passwords<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        self.check_passwords_data()?;
        self.is_updated = true;
        self.passwords_data.as_mut().unwrap().set(id, value)
    }

    pub fn remove_from_names(&mut self, id: &u32) {
        self.is_updated = true;
        self.names_data.remove(id);
    }

    pub fn remove_from_passwords(&mut self, id: &u32) -> Result<(), Error> {
        self.check_passwords_data()?;
        self.is_updated = true;
        self.passwords_data.as_mut().unwrap().remove(id);
        Ok(())
    }

    pub fn get_names_records_count(&self) -> usize {
        self.names_data.get_records_count()
    }

    pub fn get_passwords_records_count(&self) -> Result<usize, Error> {
        self.check_passwords_data()?;
        Ok(self.passwords_data.as_ref().unwrap().get_records_count())
    }

    pub fn build_names_passwords_file_info(processor2: Arc<dyn CryptoProcessor + Send + Sync>) -> Result<IdValueMap, Error> {
        let mut h = IdValueMap::new(processor2)?;
        h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();
        h.add_with_id(FILE_LOCATION_ID, build_fake_qs3_file_location()).unwrap();
        Ok(h)
    }

    pub fn build_file2_info(&mut self) -> Result<(), Error> {
        self.check_passwords_data()?;
        self.passwords_data.as_mut().unwrap().add_with_id(FILE_LOCATION_ID, build_fake_qs3_file_location())
    }

    pub fn build_encryption_keys(&mut self, password_hash: &Vec<u8>,
                                 password2_hash: &Vec<u8>) -> Result<([u8;32], [u8;32]), Error> {
        build_encryption_keys(&mut self.names_data, password_hash, password2_hash)
    }

    pub fn get_encryption_algorithms(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        get_encryption_algorithms(&self.names_data)
    }

    pub fn modify_header_algorithm_properties(&mut self) -> Result<(), Error> {
        modify_header_algorithm_properties(&mut self.names_data)
    }

    pub fn set_argon2_in_header(&mut self, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        set_argon2_in_header(&mut self.names_data, iterations, parallelism, memory)
    }

    pub fn set_file_location_qs3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<(), Error> {
        set_file_location_qs3(&mut self.names_data, file_name, s3_key)
    }

    pub fn set_file2_location_qs3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<(), Error> {
        self.check_passwords_data()?;
        set_file_location_qs3(self.passwords_data.as_mut().unwrap(), file_name, s3_key)
    }
}

fn build_encryption_processor(algorithm: u8, encryption_key: [u8; 32], data: &mut Vec<u8>)
    -> Result<Arc<dyn CryptoProcessor>, Error> {
    let mut algorithm_parameters = vec![algorithm];
    match algorithm {
        ENCRYPTION_ALGORITHM_AES => {
            let processor = build_aes_processor(algorithm_parameters, encryption_key)?;
            Ok(processor)
        },
        ENCRYPTION_ALGORITHM_CHACHA20 => {
            let salt = build_chacha_salt();
            algorithm_parameters.extend_from_slice(&salt);
            data.extend_from_slice(&salt);
            let processor = build_chacha_processor(algorithm_parameters, encryption_key)?;
            Ok(processor)
        },
        _ => Err(build_unsupported_algorithm_error())
    }
}


// validate data using sha256
pub fn add_data_hash_and_hmac(data: &mut Vec<u8>, encryption_key: [u8; 32]) -> Result<(), Error> {
    let mut mac: HmacSha256 = KeyInit::new_from_slice(&encryption_key)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(data);
    let hash1 = mac.finalize();
    let bytes1 = hash1.into_bytes();
    data.extend_from_slice(&bytes1[..]);

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let hash_bytes = hash.as_slice();
    data.extend_from_slice(hash_bytes);

    Ok(())
}

fn encrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    processor.encode_bytes(&mut data[offset..length])
}

pub fn decrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    processor.decode_bytes(&mut data[offset..length])
}

fn load_encryption_processor(alg1: u8, encryption_key: [u8; 32], data: &Vec<u8>, offset: usize)
    -> Result<(Arc<dyn CryptoProcessor>, usize), Error> {
    match alg1 {
        ENCRYPTION_ALGORITHM_AES=> Ok((AesProcessor::new(encryption_key), offset)),
        ENCRYPTION_ALGORITHM_CHACHA20 => {
            let mut iv = [0u8; 12];
            let end = offset + 12;
            iv.copy_from_slice(&data[offset..end]);
            Ok((ChachaProcessor::new(encryption_key, iv), end))
        },
        _ => Err(build_unsupported_algorithm_error())
    }
}

pub fn validate_data_hmac(encryption_key: &[u8; 32], data: &Vec<u8>, length: usize) -> Result<usize, Error> {
    let mut l = length;
    if l < 32 {
        return Err(build_corrupted_data_error("validate_data_hmac"))
    }
    l -= 32;
    let mut mac: HmacSha256 = KeyInit::new_from_slice(encryption_key)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    mac.update(&data[0..l]);
    let hash = mac.finalize();
    let hash_bytes = hash.into_bytes();
    if *hash_bytes != data[l..l+32] {
        return Err(Error::new(ErrorKind::InvalidData, "file hash does not match"))
    }
    Ok(l)
}

pub fn validate_data_hash(data: &Vec<u8>) -> Result<usize, Error> {
    let mut l = data.len();
    if l < 32 {
        return Err(build_corrupted_data_error("validate_data_hash"))
    }
    l -= 32;
    let mut hasher = Sha256::new();
    hasher.update(&data[0..l]);
    let hash = hasher.finalize();
    let hash_bytes = hash.as_slice();
    if *hash_bytes != data[l..l+32] {
        return Err(Error::new(ErrorKind::Unsupported, "file hash does not match"))
    }
    Ok(l)
}

fn build_fake_qs3_file_location() -> Vec<u8> {
    vec![0]
}

pub fn build_qs3_file_location(file_name: String, s3_key: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(FILE_LOCATION_QS3);
    build_qs3_location_data(&mut result, file_name, s3_key);
    result
}

pub fn build_qs3_location_data(result: &mut Vec<u8>, s3_path: String, s3_key: Vec<u8>) {
    let bytes = s3_path.as_bytes();
    result.push(bytes.len() as u8);
    result.extend_from_slice(bytes);
    result.push(s3_key.len() as u8);
    result.extend_from_slice(&s3_key);
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::pman::data_file::data_file::{add_data_hash_and_hmac, validate_data_hash, validate_data_hmac};

    #[test]
    fn test_hash_hmac() -> Result<(), Error> {
        const L: usize = 100;
        let mut data_bytes = [0u8; L];
        OsRng.fill_bytes(&mut data_bytes);
        let mut data = Vec::from(data_bytes);
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        add_data_hash_and_hmac(&mut data, key.clone())?;
        let l1 = validate_data_hash(&data)?;
        let l2 = validate_data_hmac(&key, &data, l1)?;
        assert_eq!(l2, L);
        Ok(())
    }
}
