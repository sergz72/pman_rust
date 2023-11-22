/*

password1,2 -> hashed using sha256

common data structure
|  | encryption_algorithm_properties (iv) for sha256(password1_hash+password2_hash), map1_encryption1_algorithm
|* |-map1 -> id_value_map (encrypted with password1_hash, password1_hash_algorithm properties, map1_encryption2_algorithm)
|* | encryption_algorithm_properties (iv) for sha256(password2_hash+password1_hash), map2_encryption1_algorithm
|*&|-map2 -> id_value_map (encrypted with password2_hash,password1_hash_algorithm properties, map2_encryption2_algorithm)
|  |-hmacsha256 for file data (using password1_hash, names_file_hash_algorithm properties)
|----sha256 for file data

* - encrypted using password1_hash, names_file_info_encryption1_algorithm
& - encrypted using password2_hash, passwords_file_info_encryption1_algorithm

main database file structure
|--|-header -> id_value_map
|  |     database version
|  |     password1_hash_algorithm properties (supported: argon2)
|  |     map1_encryption1_algorithm properties (supported: chacha20)
|  |     map1_encryption2_algorithm properties (supported: aes)
|  | encryption_algorithm_properties (iv) for sha256(password1_hash+password2_hash), names_map_info_encryption1_algorithm
|--| common data structure
|  | map1 contains
|  |     file1 locations
|  |     password2_hash_algorithm properties (supported: argon2)
|  |     map2_encryption1_algorithm properties (supported: chacha20)
|  |     map2_encryption2_algorithm properties (supported: aes)
|  | map2 contains
|  |     file2 locations

names&passwords file structure -> common data structure
file is divided to two parts -> file1 & file2 and saved in different locations in cloud

*/

use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::vec;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crate::crypto::{AesProcessor, ChachaProcessor, CryptoProcessor, NoEncryptionProcessor};
use crate::error_builders::{build_corrupted_data_error, build_unsupported_algorithm_error};
use crate::pman::id_value_map::id_value_map::{ByteValue, IdValueMap};
use crate::pman::ids::{DATABASE_VERSION_ID, ENCRYPTION_ALGORITHM1_PROPERTIES_ID,
                       ENCRYPTION_ALGORITHM2_PROPERTIES_ID, FILE_LOCATION_ID,
                       HASH_ALGORITHM_PROPERTIES_ID, HISTORY_LENGTH_ID};
use crate::pman::data_file::{build_qs3_file_location, DataFile, validate_data_hash};

const DATABASE_VERSION_MIN: u16 = 0x100; // 1.0
const DATABASE_VERSION_MAX: u16 = 0x100; // 1.0
const DATABASE_VERSION_1: u16 = 0x100; // 1.0
pub const DEFAULT_HISTORY_LENGTH: u8 = 5;
pub const HASH_ALGORITHM_ARGON2: u8 = 1;
pub const DEFAULT_ARGON2_ITERATIONS: u8 = 2;
pub const DEFAULT_ARGON2_MEMORY: u16 = 64;
pub const DEFAULT_ARGON2_PARALLELISM: u8 = 6;
pub const ENCRYPTION_ALGORITHM_AES: u8 = 2;
pub const ENCRYPTION_ALGORITHM_CHACHA20: u8 = 3;
pub const FILE_LOCATION_QS3: u8 = 1;

pub struct PmanDatabaseProperties {
    password_hash: Vec<u8>,
    password2_hash: Vec<u8>,
    map1_encryption_key1: [u8; 32],
    map1_encryption_key2: [u8; 32],
    map2_encryption_key1: [u8; 32],
    map2_encryption_key2: [u8; 32],
    header: IdValueMap,
    main_data: DataFile,
    names_passwords_data: Option<DataFile>,
    is_updated: bool,
    alg1: u8,
    alg21: u8,
    processor12: Arc<dyn CryptoProcessor + Send + Sync>,
    processor22: Arc<dyn CryptoProcessor + Send + Sync>,
    history_length: usize
}

pub struct PmanDatabaseFile {
    data: Option<Vec<u8>>,
    data_length: usize,
    properties: Option<PmanDatabaseProperties>
}

impl PmanDatabaseProperties {
    fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseProperties, Error> {
        let mut h = IdValueMap::new(NoEncryptionProcessor::new())?;
        h.add_with_id(DATABASE_VERSION_ID, DATABASE_VERSION_1.to_le_bytes().to_vec()).unwrap();
        h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();
        h.add_with_id(HISTORY_LENGTH_ID, vec![DEFAULT_HISTORY_LENGTH]).unwrap();

        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let a1 = alg1[0];
        // initially generating random key - it will be overwritten on save
        let mut map1_encryption_key1 = [0u8; 32];
        OsRng.fill_bytes(&mut map1_encryption_key1);
        let mut map1_encryption_key2 = [0u8; 32];
        OsRng.fill_bytes(&mut map1_encryption_key2);
        let processor12 =
            build_encryption_processor(alg2, map1_encryption_key2)?;

        let map1 = DataFile::build_names_passwords_file_info(processor12.clone())?;

        let (alg21, alg22) = get_encryption_algorithms(&map1)?;
        let a2 = alg21[0];
        // initially generating random key - it will be overwritten on save
        let mut map2_encryption_key1 = [0u8; 32];
        OsRng.fill_bytes(&mut map2_encryption_key1);
        let mut map2_encryption_key2 = [0u8; 32];
        OsRng.fill_bytes(&mut map2_encryption_key2);
        let processor22 =
            build_encryption_processor(alg22, map2_encryption_key2)?;

        let mut main_data = DataFile::new(map1, processor22.clone())?;
        main_data.build_file2_info()?;

        let names_passwords_data =
            Some(DataFile::new(IdValueMap::new(processor12.clone())?,
                               processor22.clone())?);
        Ok(PmanDatabaseProperties{
            password_hash,
            password2_hash,
            map1_encryption_key1,
            map1_encryption_key2,
            map2_encryption_key1,
            map2_encryption_key2,
            header: h,
            main_data,
            names_passwords_data,
            is_updated: true,
            alg1: a1,
            alg21: a2,
            processor12,
            processor22,
            history_length: DEFAULT_HISTORY_LENGTH as usize
        })
    }

    fn pre_open(data: &mut Vec<u8>, data_length: usize, password_hash: Vec<u8>,
                password2_hash: Vec<u8>) -> Result<PmanDatabaseProperties, Error> {
        let (h, offset) = IdValueMap::load(data, 0, NoEncryptionProcessor::new())?;
        let _v = validate_database_version(&h)?;
        let history_length = get_history_length(&h)?;
        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let a1 = alg1[0];
        let (map1_encryption_key1, map1_encryption_key2) =
            build_encryption_keys(&h, &password_hash, &password2_hash)?;
        let processor12 =
            build_encryption_processor(alg2, map1_encryption_key2)?;
        let mut main_data =
            DataFile::pre_load(data, offset, data_length, map1_encryption_key1, a1,
                               processor12.clone())?;

        let (map2_encryption_key1, map2_encryption_key2) =
            main_data.build_encryption_keys(&password2_hash, &password_hash)?;
        let (alg21, alg22) = main_data.get_encryption_algorithms()?;
        let a2 = alg21[0];
        let processor22 =
            build_encryption_processor(alg22, map2_encryption_key2)?;
        main_data.load(data, map2_encryption_key1, a2, processor22.clone())?;

        let properties = PmanDatabaseProperties{
            password_hash,
            password2_hash,
            map1_encryption_key1,
            map1_encryption_key2,
            map2_encryption_key1,
            map2_encryption_key2,
            header: h,
            main_data,
            names_passwords_data: None,
            is_updated: false,
            alg1: a1,
            alg21: a2,
            processor12,
            processor22,
            history_length
        };

        Ok(properties)
    }

    fn open(&mut self,  data1: Vec<u8>, data2: Vec<u8>) -> Result<(), Error> {
        if self.names_passwords_data.is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "names_passwords_data must be None"));
        }
        let mut data = join_data(data1, data2)?;
        let l = validate_data_hash(&data)?;
        let mut npdata = DataFile::pre_load(&mut data, 0, l, self.map1_encryption_key1,
                                        self.alg1, self.processor12.clone())?;
        npdata.load(&mut data, self.map2_encryption_key1, self.alg21, self.processor22.clone())?;
        self.names_passwords_data = Some(npdata);
        Ok(())
    }

    fn save(&mut self) -> Result<(Option<Vec<u8>>, Option<(Vec<u8>, Vec<u8>)>), Error> {
        if self.names_passwords_data.is_none() {
            return Err(build_names_passwords_file_not_initialized_error());
        }
        let data1 = if self.is_updated {
            let mut output = Vec::new();

            // main header
            modify_header_algorithm_properties(&mut self.header)?;
            self.header.save(&mut output, None)?;

            // names info
            self.main_data.modify_header_algorithm_properties()?;
            let (alg1, alg2) = get_encryption_algorithms(&mut self.header)?;
            self.alg1 = alg1[0];
            (self.map1_encryption_key1, self.map1_encryption_key2) =
                build_encryption_keys(&mut self.header, &self.password_hash, &self.password2_hash)?;
            self.processor12 = build_encryption_processor(alg2, self.map1_encryption_key2)?;

            let (alg21, alg22) = self.main_data.get_encryption_algorithms()?;
            self.alg21 = alg21[0];
            (self.map2_encryption_key1, self.map2_encryption_key2) =
                self.main_data.build_encryption_keys(&self.password2_hash, &self.password_hash)?;
            self.processor22 = build_encryption_processor(alg22, self.map2_encryption_key2)?;

            self.main_data.save(&mut output, self.map1_encryption_key1, self.alg1, Some(self.processor12.clone()),
                                self.map2_encryption_key1, self.alg21, Some(self.processor22.clone()))?;
            Some(output)
        } else {None};
        let mut output2 = Vec::new();
        self.names_passwords_data.as_mut().unwrap()
            .save(&mut output2, self.map1_encryption_key1, self.alg1, Some(self.processor12.clone()),
                  self.map2_encryption_key1, self.alg21, Some(self.processor22.clone()))?;
        let data2 = split_data(output2);
        Ok((data1, data2))
    }

    fn get_from_names<T: ByteValue>(&self, id: u32) -> Result<T, Error> {
        if let Some(p) = &self.names_passwords_data {
            return p.get_from_names(id);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn mget_from_names<T: ByteValue>(&self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &self.names_passwords_data {
            return p.mget_from_names(ids);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn get_indirect_from_names<T: ByteValue>(&self, id: u32) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &self.names_passwords_data {
            return p.get_indirect_from_names(id);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn add_to_names<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.names_passwords_data {
            return p.add_to_names(value);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn set_in_names<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.names_passwords_data {
            return p.set_in_names(id, value);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn get_from_passwords<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        if let Some(p) = &mut self.names_passwords_data {
            return p.get_from_passwords(id);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn add_to_passwords<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.names_passwords_data {
            return p.add_to_passwords(value);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn set_in_passwords<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.names_passwords_data {
            return p.set_in_passwords(id, value);
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn remove_from_names(&mut self, id: &u32) -> Result<(), Error> {
        if let Some(p) = &mut self.names_passwords_data {
            p.remove_from_names(id);
            return Ok(());
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn remove_from_passwords(&mut self, id: &u32) -> Result<(), Error> {
        if let Some(p) = &mut self.names_passwords_data {
            p.remove_from_passwords(id)
        } else {
            Err(build_names_passwords_file_not_initialized_error())
        }
    }

    fn get_names_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.names_passwords_data {
            return Ok(p.get_names_records_count());
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn get_passwords_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.names_passwords_data {
            return p.get_passwords_records_count();
        }
        Err(build_names_passwords_file_not_initialized_error())
    }

    fn get_history_length(&self) -> usize {
        self.history_length
    }

    fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        if let Some(p) = &mut self.names_passwords_data {
            p.set_updated();
        } else {
            return Err(build_names_passwords_file_not_initialized_error());
        }
        self.is_updated = true;
        match hash_id {
            0 => set_argon2_in_header(&mut self.header, iterations, parallelism, memory),
            1 => self.main_data.set_argon2_in_header(iterations, parallelism, memory),
            _ => Err(Error::new(ErrorKind::InvalidInput, "wrong hash id"))
        }
    }

    fn set_file1_location_qs3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<(), Error> {
        self.is_updated = true;
        self.main_data.set_file_location_qs3(file_name, s3_key)
    }

    fn set_file2_location_qs3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<(), Error> {
        self.is_updated = true;
        self.main_data.set_file2_location_qs3(file_name, s3_key)
    }

    fn get_location_data(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.main_data.get_location_data()
    }
}

impl PmanDatabaseFile {
    pub fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseFile, Error> {
        let properties =
            PmanDatabaseProperties::new(password_hash, password2_hash)?;
        Ok(PmanDatabaseFile{
            data: None,
            data_length: 0,
            properties: Some(properties),
        })
    }

    pub fn prepare(data: Vec<u8>) -> Result<PmanDatabaseFile, Error> {
        let data_length = validate_data_hash(&data)?;
        Ok(PmanDatabaseFile{
            data: Some(data),
            data_length,
            properties: None
        })
    }

    pub fn pre_open(&mut self, password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<(), Error> {
        if self.properties.is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "database properties already initialised"))
        }
        if self.data.is_none() {
            return Err(Error::new(ErrorKind::NotFound, "data is not initialised"))
        }
        let properties =
            PmanDatabaseProperties::pre_open(self.data.as_mut().unwrap(),
                                             self.data_length, password_hash, password2_hash)?;
        self.properties = Some(properties);
        Ok(())
    }

    pub fn open(&mut self, data1: Vec<u8>, data2: Vec<u8>) -> Result<(), Error> {
        if self.properties.is_none() {
            return Err(build_properties_not_initialized_error())
        }
        self.properties.as_mut().unwrap().open(data1, data2)
    }

    pub fn save(&mut self) -> Result<(Option<Vec<u8>>, Option<(Vec<u8>, Vec<u8>)>), Error> {
        if self.properties.is_none() {
            return Err(build_properties_not_initialized_error())
        }
        self.properties.as_mut().unwrap().save()
    }

    pub fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.set_argon2(hash_id, iterations, parallelism, memory);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_from_names<T: ByteValue>(&self, id: u32) -> Result<T, Error> {
        if let Some(p) = &self.properties {
            return p.get_from_names(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn mget_from_names<T: ByteValue>(&self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &self.properties {
            return p.mget_from_names(ids);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_indirect_from_names<T: ByteValue>(&self, id: u32) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &self.properties {
            return p.get_indirect_from_names(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn add_to_names<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.properties {
            return p.add_to_names(value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_in_names<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.set_in_names(id, value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_from_passwords<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        if let Some(p) = &mut self.properties {
            return p.get_from_passwords(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn add_to_passwords<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.properties {
            return p.add_to_passwords(value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_in_passwords<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.set_in_passwords(id, value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn remove_from_names(&mut self, id: &u32) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.remove_from_names(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn remove_from_passwords(&mut self, id: &u32) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.remove_from_passwords(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_names_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.properties {
            return p.get_names_records_count()
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_passwords_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.properties {
            return p.get_passwords_records_count()
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_history_length(&self) -> Result<usize, Error> {
        if let Some(p) = &self.properties {
            return Ok(p.get_history_length())
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_file1_location_qs3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            p.set_file1_location_qs3(file_name, s3_key)
        } else {
            Err(build_properties_not_initialized_error())
        }
    }

    pub fn set_file2_location_qs3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            p.set_file2_location_qs3(file_name, s3_key)
        } else {
            Err(build_properties_not_initialized_error())
        }
    }

    pub fn get_location_data(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if let Some(p) = &self.properties {
            p.get_location_data()
        } else {
            Err(build_properties_not_initialized_error())
        }
    }
}

pub fn build_properties_not_initialized_error() -> Error {
    Error::new(ErrorKind::NotFound, "database properties aren't initialised")
}

pub fn build_names_passwords_file_not_initialized_error() -> Error {
    Error::new(ErrorKind::NotFound, "names&passwords file is not initialised")
}

fn build_encryption_processor(algorithm_parameters: Vec<u8>, encryption_key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor + Send + Sync>, Error> {
    if algorithm_parameters.len() == 0 {
        return Err(build_corrupted_data_error("build_encryption_processor"))
    }
    match algorithm_parameters[0] {
        ENCRYPTION_ALGORITHM_AES => build_aes_processor(algorithm_parameters, encryption_key),
        ENCRYPTION_ALGORITHM_CHACHA20 => build_chacha_processor(algorithm_parameters, encryption_key),
        _ => Err(build_unsupported_algorithm_error())
    }
}

pub fn set_file_location_qs3(header: &mut IdValueMap, file_name: String, s3_key: Vec<u8>) -> Result<(), Error> {
    header.set(FILE_LOCATION_ID, build_qs3_file_location(file_name, s3_key))
}

pub fn set_argon2_in_header(header: &mut IdValueMap, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
    let salt = build_argon2_salt();
    header.set(HASH_ALGORITHM_PROPERTIES_ID, build_argon2_properties(iterations, parallelism, memory, salt))
}

pub fn build_aes_processor(parameters: Vec<u8>, key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor + Send + Sync>, Error> {
    if parameters.len() != 1 {
        return Err(build_corrupted_data_error("build_aes_processor"));
    }
    Ok(AesProcessor::new(key))
}

pub fn build_chacha_processor(parameters: Vec<u8>, key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor + Send + Sync>, Error> {
    if parameters.len() != 13 {
        return Err(build_corrupted_data_error("build_chacha_processor"));
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&parameters[1..13]);
    Ok(ChachaProcessor::new(key, iv))
}

pub fn modify_header_algorithm_properties(header: &mut IdValueMap) -> Result<(), Error> {
    let hash_props = header.get(HASH_ALGORITHM_PROPERTIES_ID)?;
    header.set(HASH_ALGORITHM_PROPERTIES_ID, modify_algorithm_properties(hash_props)?)?;
    let alg1_props = header.get(ENCRYPTION_ALGORITHM1_PROPERTIES_ID)?;
    header.set(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, modify_algorithm_properties(alg1_props)?)?;
    let alg2_props = header.get(ENCRYPTION_ALGORITHM2_PROPERTIES_ID)?;
    header.set(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, modify_algorithm_properties(alg2_props)?)
}

fn modify_algorithm_properties(mut properties: Vec<u8>) -> Result<Vec<u8>, Error> {
    if properties.len() == 0 {
        return Err(build_corrupted_data_error("modify_algorithm_properties"));
    }
    match properties[0] {
        HASH_ALGORITHM_ARGON2 => {
            set_argon2_salt(&mut properties, build_argon2_salt())?;
            Ok(properties)
        },
        ENCRYPTION_ALGORITHM_AES => Ok(properties),
        ENCRYPTION_ALGORITHM_CHACHA20 => Ok(properties),
        _ => Err(Error::new(ErrorKind::Unsupported, "unsupported algorithm"))
    }
}

fn get_history_length(header: &IdValueMap) -> Result<usize, Error> {
    let l: Vec<u8> = header.get(HISTORY_LENGTH_ID)?;
    if l.len() != 1 {
        return Err(build_corrupted_data_error("get_history_length"));
    }
    Ok(l[0] as usize)
}

pub fn get_encryption_algorithms(header: &IdValueMap) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let alg1 = header.get(ENCRYPTION_ALGORITHM1_PROPERTIES_ID)?;
    let alg2 = header.get(ENCRYPTION_ALGORITHM2_PROPERTIES_ID)?;
    return Ok((alg1, alg2))
}

pub fn build_encryption_keys(header: &IdValueMap, password_hash: &Vec<u8>,
                             password2_hash: &Vec<u8>) -> Result<([u8;32], [u8;32]), Error> {
    let alg: Vec<u8> = header.get(HASH_ALGORITHM_PROPERTIES_ID)?;
    if alg.len() == 0 {
        return Err(build_corrupted_data_error("build_encryption_keys"))
    }
    let mut hasher = Sha256::new();
    hasher.update(password_hash);
    hasher.update(password2_hash);
    let hash = hasher.finalize();
    let passwords_hash = Vec::from(hash.as_slice());
    match alg[0] {
        HASH_ALGORITHM_ARGON2 => {
            let key1 = build_argon2_key(alg.clone(), &passwords_hash)?;
            let key2 = build_argon2_key(alg, password_hash)?;
            Ok((key1, key2))
        },
        _ => Err(Error::new(ErrorKind::Unsupported, "unsupported hash algorithm"))
    }
}

fn validate_database_version(header: &IdValueMap) -> Result<usize, Error> {
    let version_bytes: Vec<u8> = header.get(DATABASE_VERSION_ID)?;
    if version_bytes.len() != 2 {
        return Err(build_corrupted_data_error("validate_database_version"))
    }
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&version_bytes);
    let version = u16::from_le_bytes(bytes);
    if version < DATABASE_VERSION_MIN || version > DATABASE_VERSION_MAX {
        return Err(Error::new(ErrorKind::Unsupported, "unsupported database version"))
    }
    Ok(version as usize)
}

pub fn default_aes_properties() -> Vec<u8> {
    vec![ENCRYPTION_ALGORITHM_AES]
}

pub fn default_chacha_properties() -> Vec<u8> {
    vec![ENCRYPTION_ALGORITHM_CHACHA20]
}

pub fn build_argon2_key(algorithm_properties: Vec<u8>, password_hash: &Vec<u8>) -> Result<[u8; 32], Error> {
    if algorithm_properties.len() != 21 {
        return Err(build_corrupted_data_error("build_argon2_key"))
    }
    let iterations = algorithm_properties[1];
    let parallelism = algorithm_properties[2];
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&algorithm_properties[3..5]);
    let memory = (u16::from_le_bytes(bytes) as u32) * 1024; // in kb
    let salt = &algorithm_properties[5..21];
    let params = Params::new(memory as u32, iterations as u32, parallelism as u32, None)
        .map_err(|e|Error::new(ErrorKind::Other, e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0u8; 32];
    argon2.hash_password_into(password_hash.as_slice(), salt, &mut hash)
        .map_err(|e|Error::new(ErrorKind::Other, e.to_string()))?;
    Ok(hash)
}

pub fn default_argon2_properties() -> Vec<u8> {
    build_argon2_properties(DEFAULT_ARGON2_ITERATIONS,
                            DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_MEMORY,
                        build_argon2_salt())
}

pub fn build_argon2_properties(iterations: u8, parallelism: u8, memory: u16, salt: [u8; 16]) -> Vec<u8> {
    let mut result = vec![HASH_ALGORITHM_ARGON2, iterations, parallelism];
    result.extend_from_slice(&memory.to_le_bytes());
    result.extend_from_slice(&salt);
    result
}

fn set_argon2_salt(input: &mut Vec<u8>, salt: [u8; 16]) -> Result<(), Error> {
    if input.len() != 21 {
        Err(build_corrupted_data_error("set_argon2_salt"))
    } else {
        input[5..21].copy_from_slice(&salt);
        Ok(())
    }
}
pub fn build_argon2_salt() -> [u8; 16] {
    let mut result = [0u8; 16];
    OsRng.fill_bytes(&mut result);
    result
}

pub fn build_chacha_salt() -> [u8; 12] {
    let mut result = [0u8; 12];
    OsRng.fill_bytes(&mut result);
    result
}

fn split_data(data: Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
    if data.len() == 0 {
        return None;
    }
    let mut to_first = true;
    let mut vec1 = Vec::new();
    let mut vec2 = Vec::new();
    for b in data {
        if to_first {
            vec1.push(b);
        } else {
            vec2.push(b);
        }
        to_first = !to_first;
    }
    Some((vec1, vec2))
}

fn join_data(data1: Vec<u8>, data2: Vec<u8>) -> Result<Vec<u8>, Error> {
    let l1 = data1.len();
    let l2 = data2.len();
    if l1 < l2 || l1 > l2 + 1 {
        return Err(build_corrupted_data_error("join_data"));
    }
    let mut result = Vec::new();
    for i in 0..l1 {
        result.push(data1[i]);
        if i < l2 {
            result.push(data2[i]);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::{Rng, RngCore};
    use rand::distributions::Standard;
    use rand::rngs::OsRng;
    use crate::pman::pman_database_file::{join_data, PmanDatabaseFile, split_data};

    #[test]
    fn test_create() -> Result<(), Error> {
        let mut hash1 = [0u8; 32];
        OsRng.fill_bytes(&mut hash1);
        let mut hash2 = [0u8; 32];
        OsRng.fill_bytes(&mut hash2);
        let hash1_vec = Vec::from(hash1);
        let hash2_vec = Vec::from(hash2);
        let mut db = PmanDatabaseFile::new(hash1_vec.clone(), hash2_vec.clone())?;
        let (data1, data2) = db.save()?;
        assert!(data1.is_some());
        assert!(data2.is_some());
        let mut db2 = PmanDatabaseFile::prepare(data1.unwrap())?;
        db2.pre_open(hash1_vec, hash2_vec)?;
        let (d2, d3) = data2.unwrap();
        db2.open(d2, d3)
    }

    #[test]
    fn test_split_join() -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        for _i in 0..1000 {
            let count: usize = rng.gen_range(10..2000);
            let values: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(count).collect();
            let (v1, v2) = split_data(values.clone()).unwrap();
            assert_eq!(v2.len(), values.len() / 2);
            assert_eq!(v2.len()+v1.len(), values.len());
            let joined = join_data(v1, v2)?;
            assert_eq!(joined, values);
        }
        Ok(())
    }
}