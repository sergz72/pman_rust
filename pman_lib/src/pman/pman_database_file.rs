/*

password1,2 -> hashed using sha256

database file structure
|--|-header -> id_value_map
|  |     database version
|  |     names_file_hash_algorithm properties (supported: argon2)
|  |     names_file_info_encryption1_algorithm properties (supported: chacha20)
|  |     names_file_encryption2_algorithm properties (supported: aes)
|* |-names_files_info -> id_value_map (encrypted with password1_hash, names_file_hash_algorithm properties, names_file_encryption2_algorithm)
|* |     names files locations
|* |     passwords_file_hash_algorithm properties (supported: argon2)
|* |     passwords_file_info_encryption1_algorithm properties (supported: chacha20)
|* |     passwords_file_encryption2_algorithm properties (supported: aes)
|*&|-passwords_files_info -> id_value_map (encrypted with password2_hash,passwords_file_hash_algorithm properties, passwords_file_encryption2_algorithm)
|*&|     passwords files locations
|  |-hmacsha256 for file data (using password1_hash, names_file_hash_algorithm properties)
|----sha256 for file data

* - encrypted using password1_hash, names_file_info_encryption1_algorithm
& - encrypted using password2_hash, passwords_file_info_encryption1_algorithm

names file structure
|* | encryption_algorithm_properties (iv)
|* | entities -> id_value_map (encrypted with password1_hash,names_file_hash_algorithm properties, names_file_encryption2_algorithm)
|* | names -> id_value_map (encrypted with password1_hash,names_file_hash_algorithm properties, names_file_encryption2_algorithm)
|  |-hmacsha256 for file data (using password1_hash, names_file_hash_algorithm properties)
|----sha256 for file data

passwords file structure
|& | encryption_algorithm_properties (iv)
|& | passswords -> id_value_map (encrypted with password2_hash,passsords_file_hash_algorithm properties, passwords_file_encryption2_algorithm)
|  |-hmacsha256 for file data (using password2_hash, passwords_file_hash_algorithm properties
|----sha256 for file data

*/

use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crate::crypto::{AesProcessor, ChachaProcessor, CryptoProcessor, NoEncryptionProcessor};
use crate::error_builders::build_corrupted_data_error;
use crate::pman::id_value_map::id_value_map::{ByteValue, IdValueMap};
use crate::pman::ids::{DATABASE_VERSION_ID, ENCRYPTION_ALGORITHM1_PROPERTIES_ID, ENCRYPTION_ALGORITHM2_PROPERTIES_ID, FILES_LOCATIONS_ID, HASH_ALGORITHM_PROPERTIES_ID, HISTORY_LENGTH_ID};
use crate::pman::data_file::{build_local_file_location, build_s3_file_location, DataFile};
use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;
use crate::structs_interfaces::FileAction;

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
pub const FILE_LOCATION_LOCAL: u8 = 1;
pub const FILE_LOCATION_S3: u8 = 2;
pub const FILE_LOCATION_REDIS: u8 = 3;

pub struct PmanDatabaseProperties {
    password_hash: Vec<u8>,
    password2_hash: Vec<u8>,
    names_file_encryption_key1: [u8; 32],
    names_file_encryption_key2: [u8; 32],
    passwords_file_encryption_key1: [u8; 32],
    passwords_file_encryption_key2: [u8; 32],
    header: IdValueMap,
    names_files_info: IdValueMap,
    passwords_files_info: IdValueMap,
    names_file: Option<DataFile>,
    passwords_file: Option<DataFile>,
    local_names_file: bool,
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

type HmacSha256 = Hmac<Sha256>;

impl PmanDatabaseProperties {
    fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseProperties, Error> {
        let mut h = IdValueMap::new(NoEncryptionProcessor::new(), vec![Box::new(IdValueMapLocalDataHandler::new())])?;
        h.add_with_id(DATABASE_VERSION_ID, DATABASE_VERSION_1.to_le_bytes().to_vec()).unwrap();
        h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();
        h.add_with_id(HISTORY_LENGTH_ID, vec![DEFAULT_HISTORY_LENGTH]).unwrap();

        let (alg1, alg2) = get_encryption_algorithms(&mut h)?;
        let a1 = alg1[0];
        // initially generating random key - it will be overwritten on save
        let mut names_file_encryption_key1 = [0u8; 32];
        OsRng.fill_bytes(&mut names_file_encryption_key1);
        let mut names_file_encryption_key2 = [0u8; 32];
        OsRng.fill_bytes(&mut names_file_encryption_key2);
        let processor12 = build_encryption_processor(alg2, names_file_encryption_key2)?;
        let mut names_files_info = DataFile::build_file_info(processor12.clone(), false)?;
        let names_file = DataFile::new(&mut names_files_info, processor12.clone())?;

        let (alg21, alg22) = get_encryption_algorithms(&mut names_files_info)?;
        let a2 = alg21[0];
        // initially generating random key - it will be overwritten on save
        let mut passwords_file_encryption_key1 = [0u8; 32];
        OsRng.fill_bytes(&mut passwords_file_encryption_key1);
        let mut passwords_file_encryption_key2 = [0u8; 32];
        OsRng.fill_bytes(&mut passwords_file_encryption_key2);
        let processor22 = build_encryption_processor(alg22, passwords_file_encryption_key2)?;
        let mut passwords_files_info = DataFile::build_file_info(processor22.clone(), true)?;
        let passwords_file = DataFile::new(&mut passwords_files_info, processor22.clone())?;

        Ok(PmanDatabaseProperties{
            password_hash,
            password2_hash,
            names_file_encryption_key1,
            names_file_encryption_key2,
            passwords_file_encryption_key1,
            passwords_file_encryption_key2,
            header: h,
            names_files_info,
            passwords_files_info,
            names_file: Some(names_file),
            passwords_file: Some(passwords_file),
            local_names_file: true,
            is_updated: true,
            alg1: a1,
            alg21: a2,
            processor12,
            processor22,
            history_length: DEFAULT_HISTORY_LENGTH as usize
        })
    }

    fn pre_open(main_file_name: &String, data: &mut Vec<u8>, data_length: usize, password_hash: Vec<u8>,
                password2_hash: Vec<u8>) -> Result<(PmanDatabaseProperties, Vec<String>), Error> {
        let (handler, offset) = IdValueMapLocalDataHandler::load(data, 0)?;
        let mut h = IdValueMap::new(NoEncryptionProcessor::new(), vec![Box::new(handler)])?;
        let _v = validate_database_version(&mut h)?;
        let history_length = get_history_length(&mut h)?;
        let (alg1, alg2) = get_encryption_algorithms(&mut h)?;
        let a1 = alg1[0];
        let (names_file_encryption_key1, names_file_encryption_key2) = build_encryption_keys(&mut h, &password_hash, &password2_hash)?;
        let l2 = validate_data_hmac(&names_file_encryption_key1, data, data_length)?;
        let processor11 = build_encryption_processor(alg1, names_file_encryption_key1)?;
        decrypt_data(processor11.clone(), data, offset, l2)?;

        let processor12 = build_encryption_processor(alg2, names_file_encryption_key2)?;
        let (handler2, offset2) = IdValueMapLocalDataHandler::load(data, offset)?;
        let mut names_files_info = IdValueMap::new(processor12.clone(), vec![Box::new(handler2)])?;

        let (alg21, alg22) = get_encryption_algorithms(&mut names_files_info)?;
        let a2 = alg21[0];
        let (passwords_file_encryption_key1, passwords_file_encryption_key2) = build_encryption_keys(&mut names_files_info, &password2_hash, &password_hash)?;
        let processor21 = build_encryption_processor(alg21, passwords_file_encryption_key1)?;
        decrypt_data(processor21.clone(), data, offset2, l2)?;
        let processor22 = build_encryption_processor(alg22, passwords_file_encryption_key2)?;
        let (handler3, offset3) = IdValueMapLocalDataHandler::load(data, offset2)?;
        let mut passwords_files_info = IdValueMap::new(processor22.clone(), vec![Box::new(handler3)])?;

        if offset3 != l2 {
            return Err(build_corrupted_data_error());
        }

        let mut files_to_load = Vec::new();
        let names_file = DataFile::pre_load(main_file_name, ".names",  &mut names_files_info)?;
        let local_names_file = names_file.is_some();
        if local_names_file {
            files_to_load.push(names_file.unwrap());
        }
        let passwords_file = DataFile::pre_load(main_file_name, ".passwords", &mut passwords_files_info)?;
        if let Some(name) = passwords_file {
            files_to_load.push(name);
        }

        let properties = PmanDatabaseProperties{
            password_hash,
            password2_hash,
            names_file_encryption_key1,
            names_file_encryption_key2,
            passwords_file_encryption_key1,
            passwords_file_encryption_key2,
            header: h,
            names_files_info,
            passwords_files_info,
            names_file: None,
            passwords_file: None,
            local_names_file,
            is_updated: false,
            alg1: a1,
            alg21: a2,
            processor12,
            processor22,
            history_length
        };

        Ok((properties, files_to_load))
    }

    fn load_names_file(&mut self,  mut data: Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, Error> {
        if self.names_file.is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "names file must be None"));
        }
        let l = data.len();
        let (names_file_data, passwords_file_data) = match l {
            0 => (None, None),
            1 => if self.local_names_file { (Some(data.remove(0)), None) } else { (None, Some(data.remove(0))) },
            _ => {
                let data1 = data.remove(1);
                let data0 = data.remove(0);
                (Some(data0), Some(data1))
            }
        };
        self.names_file = Some(DataFile::load(names_file_data,
                                              &mut self.names_files_info, self.names_file_encryption_key1,
                                              self.alg1, self.processor12.clone())?);
        Ok(passwords_file_data)
    }

    fn load_passwords_file(&mut self,  passwords_file_data: Option<Vec<u8>>) -> Result<(), Error> {
        self.passwords_file = Some(DataFile::load(passwords_file_data,
                                                  &mut self.passwords_files_info,
                                                  self.passwords_file_encryption_key1, self.alg21,
                                                  self.processor22.clone())?);
        Ok(())
    }

    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        let passwords_file_data = self.load_names_file(data)?;
        self.load_passwords_file(passwords_file_data)
    }

    fn save(&mut self, file_name: &String) -> Result<Vec<FileAction>, Error> {
        let mut v = Vec::new();
        if self.is_updated {
            let mut output = Vec::new();

            // main header
            modify_header_algorithm_properties(&mut self.header)?;
            let mut data = self.header.save( None, None, None)?.unwrap();
            output.append(&mut data);
            let offset = output.len();

            // names info
            modify_header_algorithm_properties(&mut self.names_files_info)?;
            let (alg1, alg2) = get_encryption_algorithms(&mut self.header)?;
            self.alg1 = alg1[0];
            (self.names_file_encryption_key1, self.names_file_encryption_key2) =
                build_encryption_keys(&mut self.header, &self.password_hash, &self.password2_hash)?;
            self.processor12 = build_encryption_processor(alg2, self.names_file_encryption_key2)?;
            let mut data2 =
                self.names_files_info.save(Some(self.processor12.clone()), None, None)?.unwrap();
            output.append(&mut data2);
            let offset2 = output.len();

            // passwords info
            let (alg21, alg22) = get_encryption_algorithms(&mut self.names_files_info)?;
            self.alg21 = alg21[0];
            (self.passwords_file_encryption_key1, self.passwords_file_encryption_key2) =
                build_encryption_keys(&mut self.names_files_info, &self.password2_hash, &self.password_hash)?;
            self.processor22 = build_encryption_processor(alg22, self.passwords_file_encryption_key2)?;
            let mut data3 =
                self.passwords_files_info.save(Some(self.processor22.clone()), None, None)?.unwrap();
            output.append(&mut data3);
            let ol = output.len();

            // encrypt passwords info
            let processor21 = build_encryption_processor(alg21, self.passwords_file_encryption_key1)?;
            encrypt_data(processor21, &mut output, offset2, ol)?;

            // encrypt names+passwords info
            let processor11 = build_encryption_processor(alg1, self.names_file_encryption_key1)?;
            encrypt_data(processor11, &mut output, offset, ol)?;
            add_data_hash_and_hmac(&mut output, self.names_file_encryption_key1)?;
            v.push(FileAction::new(file_name.clone(), output));
        }
        let action1 =
            self.names_file.as_mut().unwrap().save(self.names_file_encryption_key1,
                                                   self.alg1, self.processor12.clone())?;
        let action2 =
            self.passwords_file.as_mut().unwrap().save(self.passwords_file_encryption_key1,
                                                       self.alg21, self.processor22.clone())?;
        if let Some(a) = action1 {
            v.push(FileAction{ file_name: file_name.clone() +  ".names", data: a })
        }
        if let Some(a) = action2 {
            v.push(FileAction{ file_name: file_name.clone() +  ".passwords", data: a })
        }
        self.is_updated = false;
        Ok(v)
    }

    fn get_from_names_file<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        if let Some(p) = &mut self.names_file {
            return p.get(id);
        }
        Err(build_names_file_not_initialized_error())
    }

    fn mget_from_names_file<T: ByteValue>(&mut self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &mut self.names_file {
            return p.mget(ids);
        }
        Err(build_names_file_not_initialized_error())
    }

    fn get_indirect_from_names_file<T: ByteValue>(&mut self, id: u32) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &mut self.names_file {
            return p.get_indirect(id);
        }
        Err(build_names_file_not_initialized_error())
    }

    fn add_to_names_file<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.names_file {
            return p.add(value);
        }
        Err(build_names_file_not_initialized_error())
    }

    fn set_in_names_file<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.names_file {
            return p.set(id, value);
        }
        Err(build_names_file_not_initialized_error())
    }

    fn get_from_passwords_file<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        if let Some(p) = &mut self.passwords_file {
            return p.get(id);
        }
        Err(build_passwords_file_not_initialized_error())
    }

    fn add_to_passwords_file<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.passwords_file {
            return p.add(value);
        }
        Err(build_passwords_file_not_initialized_error())
    }

    fn set_in_passwords_file<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.passwords_file {
            return p.set(id, value);
        }
        Err(build_passwords_file_not_initialized_error())
    }

    fn remove_from_names_file(&mut self, id: u32) -> Result<(), Error> {
        if let Some(p) = &mut self.names_file {
            p.remove(id);
            return Ok(());
        }
        Err(build_names_file_not_initialized_error())
    }

    fn remove_from_passwords_file(&mut self, id: u32) -> Result<(), Error> {
        if let Some(p) = &mut self.passwords_file {
            p.remove(id);
            return Ok(());
        }
        Err(build_passwords_file_not_initialized_error())
    }

    fn get_names_file_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.names_file {
            return Ok(p.get_records_count());
        }
        Err(build_names_file_not_initialized_error())
    }

    fn get_passwords_file_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.passwords_file {
            return Ok(p.get_records_count());
        }
        Err(build_passwords_file_not_initialized_error())
    }

    fn get_history_length(&self) -> usize {
        self.history_length
    }

    fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        if let Some(p) = &mut self.names_file {
            p.set_updated();
        } else {
            return Err(build_names_file_not_initialized_error());
        }
        if let Some(p) = &mut self.passwords_file {
            p.set_updated();
        } else {
            return Err(build_passwords_file_not_initialized_error());
        }
        self.is_updated = true;
        match hash_id {
            0 => set_argon2_in_header(&mut self.header, iterations, parallelism, memory),
            1 => set_argon2_in_header(&mut self.names_files_info, iterations, parallelism, memory),
            _ => Err(Error::new(ErrorKind::InvalidInput, "wrong hash id"))
        }
    }

    pub fn set_names_file_location_local(&mut self) -> Result<bool, Error> {
        if self.names_file.is_none() {
            return Err(build_names_file_not_initialized_error());
        }
        let updated = set_file_location_local(&mut self.names_files_info)?;
        if updated {
            self.names_file.as_mut().unwrap().update_handlers(&mut self.names_files_info)?;
            self.is_updated = true;
            self.local_names_file = true;
        }
        Ok(updated)
    }

    pub fn set_passwords_file_location_local(&mut self) -> Result<bool, Error> {
        if self.passwords_file.is_none() {
            return Err(build_passwords_file_not_initialized_error());
        }
        let updated = set_file_location_local(&mut self.passwords_files_info)?;
        if updated {
            self.passwords_file.as_mut().unwrap().update_handlers(&mut self.passwords_files_info)?;
            self.is_updated = true;
        }
        Ok(updated)
    }

    pub fn set_names_file_location_s3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<bool, Error> {
        if self.names_file.is_none() {
            return Err(build_names_file_not_initialized_error());
        }
        let updated = set_file_location_s3(&mut self.names_files_info, file_name, s3_key)?;
        if updated {
            self.names_file.as_mut().unwrap().update_handlers(&mut self.names_files_info)?;
            self.is_updated = true;
            self.local_names_file = false;
        }
        Ok(updated)
    }

    pub fn set_passwords_file_location_s3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<bool, Error> {
        if self.passwords_file.is_none() {
            return Err(build_passwords_file_not_initialized_error());
        }
        let updated = set_file_location_s3(&mut self.passwords_files_info, file_name, s3_key)?;
        if updated {
            self.passwords_file.as_mut().unwrap().update_handlers(&mut self.passwords_files_info)?;
            self.is_updated = true;
        }
        Ok(updated)
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
            properties: None,
        })
    }

    pub fn pre_open(&mut self, main_file_name: &String, password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<Vec<String>, Error> {
        if self.properties.is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "database properties already initialised"))
        }
        if self.data.is_none() {
            return Err(Error::new(ErrorKind::NotFound, "data is not initialised"))
        }
        let (properties, actions) =
            PmanDatabaseProperties::pre_open(main_file_name, self.data.as_mut().unwrap(),
                                             self.data_length, password_hash, password2_hash)?;
        self.properties = Some(properties);
        Ok(actions)
    }

    pub fn load_names_file(&mut self, data: Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, Error> {
        if self.properties.is_none() {
            return Err(build_properties_not_initialized_error())
        }
        self.properties.as_mut().unwrap().load_names_file(data)
    }

    pub fn load_passwords_file(&mut self, data: Option<Vec<u8>>) -> Result<(), Error> {
        if self.properties.is_none() {
            return Err(build_properties_not_initialized_error())
        }
        self.properties.as_mut().unwrap().load_passwords_file(data)
    }

    pub fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        if self.properties.is_none() {
            return Err(build_properties_not_initialized_error())
        }
        self.properties.as_mut().unwrap().open(data)
    }

    pub fn save(&mut self, file_name: &String) -> Result<Vec<FileAction>, Error> {
        if self.properties.is_none() {
            return Err(build_properties_not_initialized_error())
        }
        self.properties.as_mut().unwrap().save(file_name)
    }

    pub fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.set_argon2(hash_id, iterations, parallelism, memory);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_from_names_file<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        if let Some(p) = &mut self.properties {
            return p.get_from_names_file(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn mget_from_names_file<T: ByteValue>(&mut self, ids: HashSet<u32>) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &mut self.properties {
            return p.mget_from_names_file(ids);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_indirect_from_names_file<T: ByteValue>(&mut self, id: u32) -> Result<HashMap<u32, T>, Error> {
        if let Some(p) = &mut self.properties {
            return p.get_indirect_from_names_file(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn add_to_names_file<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.properties {
            return p.add_to_names_file(value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_in_names_file<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.set_in_names_file(id, value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_from_passwords_file<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        if let Some(p) = &mut self.properties {
            return p.get_from_passwords_file(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn add_to_passwords_file<T: ByteValue>(&mut self, value: T) -> Result<u32, Error> {
        if let Some(p) = &mut self.properties {
            return p.add_to_passwords_file(value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_in_passwords_file<T: ByteValue>(&mut self, id: u32, value: T) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.set_in_passwords_file(id, value);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn remove_from_names_file(&mut self, id: u32) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.remove_from_names_file(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn remove_from_passwords_file(&mut self, id: u32) -> Result<(), Error> {
        if let Some(p) = &mut self.properties {
            return p.remove_from_passwords_file(id);
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_names_file_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.properties {
            return p.get_names_file_records_count()
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_passwords_file_records_count(&self) -> Result<usize, Error> {
        if let Some(p) = &self.properties {
            return p.get_passwords_file_records_count()
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn get_history_length(&self) -> Result<usize, Error> {
        if let Some(p) = &self.properties {
            return Ok(p.get_history_length())
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_names_file_location_local(&mut self) -> Result<bool, Error> {
        if let Some(p) = &mut self.properties {
            return p.set_names_file_location_local()
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_passwords_file_location_local(&mut self) -> Result<bool, Error> {
        if let Some(p) = &mut self.properties {
            return p.set_passwords_file_location_local()
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_names_file_location_s3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<bool, Error> {
        if let Some(p) = &mut self.properties {
            return p.set_names_file_location_s3(file_name, s3_key)
        }
        Err(build_properties_not_initialized_error())
    }

    pub fn set_passwords_file_location_s3(&mut self, file_name: String, s3_key: Vec<u8>) -> Result<bool, Error> {
        if let Some(p) = &mut self.properties {
            return p.set_passwords_file_location_s3(file_name, s3_key)
        }
        Err(build_properties_not_initialized_error())
    }
}

pub fn build_properties_not_initialized_error() -> Error {
    Error::new(ErrorKind::NotFound, "database properties aren't initialised")
}

pub fn build_names_file_not_initialized_error() -> Error {
    Error::new(ErrorKind::NotFound, "names file is not initialised")
}

pub fn build_passwords_file_not_initialized_error() -> Error {
    Error::new(ErrorKind::NotFound, "passwords file is not initialised")
}

pub fn build_unsupported_algorithm_error() -> Error {
    Error::new(ErrorKind::Unsupported, "unsupported encryption algorithm")
}

fn set_file_location_local(header: &mut IdValueMap) -> Result<bool, Error> {
    if !check_file_locations(header, FILE_LOCATION_LOCAL)? {
        header.set(FILES_LOCATIONS_ID+1, build_local_file_location())?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn check_file_locations(header: &mut IdValueMap, location_to_check: u8) -> Result<bool, Error> {
    let locations: Vec<u8> = header.get(FILES_LOCATIONS_ID)?;
    for location in &locations {
        let location_data: Vec<u8> = header.get(*location as u32)?;
        if location_data.is_empty() {
            return Err(build_corrupted_data_error());
        }
        if location_data[0] == location_to_check {
            return Ok(true);
        }
    }
    if locations.len() > 1 {
        return Err(Error::new(ErrorKind::InvalidData, "multiple file locations"));
    }
    Ok(false)
}

fn set_file_location_s3(header: &mut IdValueMap, file_name: String, s3_key: Vec<u8>) -> Result<bool, Error> {
    if !check_file_locations(header, FILE_LOCATION_S3)? {
        header.set(FILES_LOCATIONS_ID+1, build_s3_file_location(file_name, s3_key))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn set_argon2_in_header(header: &mut IdValueMap, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
    let salt = build_argon2_salt();
    header.set(HASH_ALGORITHM_PROPERTIES_ID, build_argon2_properties(iterations, parallelism, memory, salt))
}

fn build_encryption_processor(algorithm_parameters: Vec<u8>, encryption_key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor + Send + Sync>, Error> {
    if algorithm_parameters.len() == 0 {
        return Err(build_corrupted_data_error())
    }
    match algorithm_parameters[0] {
        ENCRYPTION_ALGORITHM_AES => build_aes_processor(algorithm_parameters, encryption_key),
        ENCRYPTION_ALGORITHM_CHACHA20 => build_chacha_processor(algorithm_parameters, encryption_key),
        _ => Err(build_unsupported_algorithm_error())
    }
}

pub fn build_aes_processor(parameters: Vec<u8>, key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor + Send + Sync>, Error> {
    if parameters.len() != 1 {
        return Err(build_corrupted_data_error());
    }
    Ok(AesProcessor::new(key))
}

pub fn build_chacha_processor(parameters: Vec<u8>, key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor + Send + Sync>, Error> {
    if parameters.len() != 13 {
        return Err(build_corrupted_data_error());
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
        return Err(build_corrupted_data_error());
    }
    match properties[0] {
        HASH_ALGORITHM_ARGON2 => {
            set_argon2_salt(&mut properties, build_argon2_salt())?;
            Ok(properties)
        },
        ENCRYPTION_ALGORITHM_AES => Ok(properties),
        ENCRYPTION_ALGORITHM_CHACHA20 => {
            set_chacha_salt(&mut properties, build_chacha_salt())?;
            Ok(properties)
        },
        _ => Err(Error::new(ErrorKind::Unsupported, "unsupported algorithm"))
    }
}

fn encrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    processor.encode_bytes(&mut data[offset..length])
}

pub fn decrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    processor.decode_bytes(&mut data[offset..length])
}

fn get_history_length(header: &mut IdValueMap) -> Result<usize, Error> {
    let l: Vec<u8> = header.get(HISTORY_LENGTH_ID)?;
    if l.len() != 1 {
        return Err(build_corrupted_data_error());
    }
    Ok(l[0] as usize)
}

pub fn get_encryption_algorithms(header: &mut IdValueMap) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let alg1 = header.get(ENCRYPTION_ALGORITHM1_PROPERTIES_ID)?;
    let alg2 = header.get(ENCRYPTION_ALGORITHM2_PROPERTIES_ID)?;
    return Ok((alg1, alg2))
}

pub fn build_encryption_keys(header: &mut IdValueMap, password_hash: &Vec<u8>,
                             password2_hash: &Vec<u8>) -> Result<([u8;32], [u8;32]), Error> {
    let alg: Vec<u8> = header.get(HASH_ALGORITHM_PROPERTIES_ID)?;
    if alg.len() == 0 {
        return Err(build_corrupted_data_error())
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

fn validate_database_version(header: &mut IdValueMap) -> Result<usize, Error> {
    let version_bytes: Vec<u8> = header.get(DATABASE_VERSION_ID)?;
    if version_bytes.len() != 2 {
        return Err(build_corrupted_data_error())
    }
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&version_bytes);
    let version = u16::from_le_bytes(bytes);
    if version < DATABASE_VERSION_MIN || version > DATABASE_VERSION_MAX {
        return Err(Error::new(ErrorKind::Unsupported, "unsupported database version"))
    }
    Ok(version as usize)
}

// validate data using sha512
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

pub fn validate_data_hmac(encryption_key: &[u8; 32], data: &Vec<u8>, length: usize) -> Result<usize, Error> {
    let mut l = length;
    if l < 32 {
        return Err(build_corrupted_data_error())
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
        return Err(build_corrupted_data_error())
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

pub fn default_aes_properties() -> Vec<u8> {
    vec![ENCRYPTION_ALGORITHM_AES]
}

pub fn default_chacha_properties() -> Vec<u8> {
    let mut result = vec![ENCRYPTION_ALGORITHM_CHACHA20];
    result.extend_from_slice(&build_chacha_salt());
    result
}

pub fn build_argon2_key(algorithm_properties: Vec<u8>, password_hash: &Vec<u8>) -> Result<[u8; 32], Error> {
    if algorithm_properties.len() != 21 {
        return Err(build_corrupted_data_error())
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
        Err(build_corrupted_data_error())
    } else {
        input[5..21].copy_from_slice(&salt);
        Ok(())
    }
}
fn set_chacha_salt(input: &mut Vec<u8>, salt: [u8; 12]) -> Result<(), Error> {
    if input.len() != 13 {
        Err(build_corrupted_data_error())
    } else {
        input[1..13].copy_from_slice(&salt);
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

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::pman::pman_database_file::{add_data_hash_and_hmac, PmanDatabaseFile, validate_data_hash, validate_data_hmac};

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

    #[test]
    fn test_create() -> Result<(), Error> {
        let mut hash1 = [0u8; 32];
        OsRng.fill_bytes(&mut hash1);
        let mut hash2 = [0u8; 32];
        OsRng.fill_bytes(&mut hash2);
        let hash1_vec = Vec::from(hash1);
        let hash2_vec = Vec::from(hash2);
        let mut db = PmanDatabaseFile::new(hash1_vec.clone(), hash2_vec.clone())?;
        let file_name = "test_file.pdbf".to_string();
        let actions = db.save(&file_name)?;
        assert_eq!(actions.len(), 3);
        let mut db2 = PmanDatabaseFile::prepare(actions[0].get_data())?;
        let file_names = db2.pre_open(&file_name, hash1_vec, hash2_vec)?;
        assert_eq!(file_names.len(), 2);
        db2.open(vec![actions[1].get_data(), actions[2].get_data()])
    }
}