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

use std::io::{Error, ErrorKind};
use std::sync::Arc;
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crate::crypto::{AesProcessor, build_corrupted_data_error, ChachaProcessor, CryptoProcessor, NoEncryptionProcessor};
use crate::pman::id_value_map::{IdValueMap, IdValueMapLocalDataHandler};
use crate::pman::ids::{DATABASE_VERSION_ID, ENCRYPTION_ALGORITHM1_PROPERTIES_ID,
                       ENCRYPTION_ALGORITHM2_PROPERTIES_ID, HASH_ALGORITHM_PROPERTIES_ID};
use crate::pman::data_file::DataFile;
use crate::structs_interfaces::FileAction;

const DATABASE_VERSION_MIN: u16 = 0x100; // 1.0
const DATABASE_VERSION_MAX: u16 = 0x100; // 1.0
const DATABASE_VERSION_1: u16 = 0x100; // 1.0
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
    encryption_key: [u8; 32],
    encryption2_key: [u8; 32],
    header: IdValueMap,
    names_files_info: IdValueMap,
    passwords_files_info: IdValueMap,
    names_file: DataFile,
    passwords_file: DataFile,
    is_updated: bool
}

pub struct PmanDatabaseFile {
    data: Option<Vec<u8>>,
    data_length: usize,
    properties: Option<PmanDatabaseProperties>
}

type HmacSha256 = Hmac<Sha256>;

impl PmanDatabaseProperties {
    fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseProperties, Error> {
        let mut h = IdValueMap::new(NoEncryptionProcessor::new(), Box::new(IdValueMapLocalDataHandler::new()))?;
        h.add_with_id(DATABASE_VERSION_ID, DATABASE_VERSION_1.to_le_bytes().to_vec()).unwrap();
        h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();

        let (_alg1, alg2) = get_encryption_algorithms(&h)?;
        // initially generating random key - it will be overwritten on save
        let mut encryption_key = [0u8; 32];
        OsRng.fill_bytes(&mut encryption_key);
        let processor12 = build_encryption_processor(alg2, encryption_key)?;
        let names_files_info = DataFile::build_file_info(processor12.clone())?;
        let names_file = DataFile::new(processor12, &names_files_info)?;

        let (_alg21, alg22) = get_encryption_algorithms(&names_files_info)?;
        // initially generating random key - it will be overwritten on save
        let mut encryption2_key = [0u8; 32];
        OsRng.fill_bytes(&mut encryption2_key);
        let processor22 = build_encryption_processor(alg22, encryption_key)?;
        let passwords_files_info = DataFile::build_file_info(processor22.clone())?;
        let passwords_file = DataFile::new(processor22, &passwords_files_info)?;

        Ok(PmanDatabaseProperties{
            password_hash,
            password2_hash,
            encryption_key,
            encryption2_key,
            header: h,
            names_files_info,
            passwords_files_info,
            names_file,
            passwords_file,
            is_updated: true
        })
    }

    fn pre_open(data: &mut Vec<u8>, data_length: usize, password_hash: Vec<u8>,
                password2_hash: Vec<u8>) -> Result<(PmanDatabaseProperties, Vec<String>), Error> {
        let (handler, offset) = IdValueMapLocalDataHandler::load(data, 0)?;
        let h = IdValueMap::new(NoEncryptionProcessor::new(), Box::new(handler))?;
        let _v = validate_database_version(&h)?;
        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let a1 = alg1[0];
        let encryption_key = build_encryption_key(&h, &password_hash)?;
        let l2 = validate_data_hmac(&encryption_key, data, data_length)?;
        let processor11 = build_encryption_processor(alg1, encryption_key)?;
        decrypt_data(processor11.clone(), data, offset, l2)?;

        let processor12 = build_encryption_processor(alg2, encryption_key)?;
        let (handler2, offset2) = IdValueMapLocalDataHandler::load(data, offset)?;
        let names_files_info = IdValueMap::new(processor12.clone(), Box::new(handler2))?;

        let (alg21, alg22) = get_encryption_algorithms(&names_files_info)?;
        let a2 = alg21[0];
        let encryption2_key = build_encryption_key(&names_files_info, &password2_hash)?;
        let processor21 = build_encryption_processor(alg21, encryption2_key)?;
        decrypt_data(processor21.clone(), data, offset2, l2)?;
        let processor22 = build_encryption_processor(alg22, encryption2_key)?;
        let (handler3, offset3) = IdValueMapLocalDataHandler::load(data, offset2)?;
        let passwords_files_info = IdValueMap::new(processor22.clone(), Box::new(handler3))?;

        if offset3 != l2 {
            return Err(build_corrupted_data_error());
        }

        let names_file = DataFile::load(encryption_key, a1, processor12, &names_files_info)?;
        let passwords_file = DataFile::load(encryption2_key, a2, processor22, &passwords_files_info)?;

        let properties = PmanDatabaseProperties{
            password_hash,
            password2_hash,
            encryption_key,
            encryption2_key,
            header: h,
            names_files_info,
            passwords_files_info,
            names_file,
            passwords_file,
            is_updated: false
        };

        Ok((properties, Vec::new()))
    }

    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        todo!()
    }

    fn save(&mut self, file_name: String) -> Result<Vec<FileAction>, Error> {
        if self.is_updated {
            let mut output = Vec::new();
            modify_header_algorithm_properties(&mut self.header)?;
            let mut data = self.header.save(None)?.unwrap();
            output.append(&mut data);
            let offset = output.len();
            let encryption_key = build_encryption_key(&self.header, &self.password_hash)?;
            let (alg1, alg2) = get_encryption_algorithms(&self.header)?;
            let a1 = alg1[0];
            let processor12 = build_encryption_processor(alg2, encryption_key)?;
            modify_header_algorithm_properties(&mut self.names_files_info)?;
            let mut data2 = self.names_files_info.save(Some(processor12.clone()))?.unwrap();
            output.append(&mut data2);
            let offset2 = output.len();
            let encryption2_key = build_encryption_key(&self.names_files_info, &self.password2_hash)?;
            let (alg21, alg22) = get_encryption_algorithms(&self.names_files_info)?;
            let a2 = alg21[0];
            let processor22 = build_encryption_processor(alg22, encryption2_key)?;
            let mut data3 = self.passwords_files_info.save(Some(processor22.clone()))?.unwrap();
            output.append(&mut data3);
            let ol = output.len();
            let processor21 = build_encryption_processor(alg21, encryption2_key)?;
            encrypt_data(processor21, &mut output, offset2, ol - offset2)?;
            let processor11 = build_encryption_processor(alg1, encryption_key)?;
            encrypt_data(processor11, &mut output, offset, ol - offset)?;
            add_data_hash_and_hmac(&mut output, encryption_key)?;
            let action1 = self.names_file.save(file_name.clone(), encryption_key, a1, processor12, &self.names_files_info)?;
            let action2 = self.passwords_file.save(file_name.clone(), encryption2_key, a2, processor22, &self.passwords_files_info)?;
            let mut v = vec![FileAction::new(file_name, output)];
            if let Some(a) = action1 {
                v.push(a)
            }
            if let Some(a) = action2 {
                v.push(a)
            }
            Ok(v)
        } else {
            let action1 = self.names_file.save_remote(file_name.clone(), &self.names_files_info)?;
            let action2 = self.passwords_file.save_remote(file_name, &self.passwords_files_info)?;
            let mut v = Vec::new();
            if let Some(a) = action1 {
                v.push(a)
            }
            if let Some(a) = action2 {
                v.push(a)
            }
            Ok(v)
        }
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

    fn pre_open(&mut self, password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<Vec<String>, Error> {
        if self.properties.is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "database properties already initialised"))
        }
        if self.data.is_none() {
            return Err(Error::new(ErrorKind::NotFound, "data is not initialised"))
        }
        let (properties, actions) =
            PmanDatabaseProperties::pre_open(self.data.as_mut().unwrap(), self.data_length, password_hash, password2_hash)?;
        self.properties = Some(properties);
        Ok(actions)
    }

    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        if self.properties.is_none() {
            return Err(Error::new(ErrorKind::NotFound, "database properties aren't initialised"))
        }
        self.properties.as_mut().unwrap().open(data)
    }

    fn save(&mut self, file_name: String) -> Result<Vec<FileAction>, Error> {
        if self.properties.is_none() {
            return Err(Error::new(ErrorKind::NotFound, "database properties aren't initialised"))
        }
        self.properties.as_mut().unwrap().save(file_name)
    }

    fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        todo!()
    }
}

fn build_encryption_processor(algorithm_parameters: Vec<u8>, encryption_key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor>, Error> {
    if algorithm_parameters.len() == 0 {
        return Err(build_corrupted_data_error())
    }
    match algorithm_parameters[0] {
        ENCRYPTION_ALGORITHM_AES => build_aes_processor(algorithm_parameters, encryption_key),
        ENCRYPTION_ALGORITHM_CHACHA20 => build_chacha_processor(algorithm_parameters, encryption_key),
        _ => Err(Error::new(ErrorKind::Unsupported, "unsupported encryption algorithm"))
    }
}

fn build_aes_processor(parameters: Vec<u8>, key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor>, Error> {
    if parameters.len() != 1 {
        return Err(build_corrupted_data_error());
    }
    Ok(AesProcessor::new(key))
}

fn build_chacha_processor(parameters: Vec<u8>, key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor>, Error> {
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
    processor.encode_bytes(&mut data[offset..offset+length])
}

pub fn decrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    processor.decode_bytes(&mut data[offset..offset+length])
}

pub fn get_encryption_algorithms(header: &IdValueMap) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let alg1 = header.get(ENCRYPTION_ALGORITHM1_PROPERTIES_ID)?;
    let alg2 = header.get(ENCRYPTION_ALGORITHM2_PROPERTIES_ID)?;
    return Ok((alg1, alg2))
}

pub fn build_encryption_key(header: &IdValueMap, password_hash: &Vec<u8>) -> Result<[u8;32], Error> {
    let alg: Vec<u8> = header.get(HASH_ALGORITHM_PROPERTIES_ID)?;
    if alg.len() == 0 {
        return Err(build_corrupted_data_error())
    }
    match alg[0] {
        HASH_ALGORITHM_ARGON2 => build_argon2_key(alg, password_hash),
        _ => Err(Error::new(ErrorKind::Unsupported, "unsupported hash algorithm"))
    }
}

fn validate_database_version(header: &IdValueMap) -> Result<usize, Error> {
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
fn add_data_hash_and_hmac(data: &mut Vec<u8>, encryption_key: [u8; 32]) -> Result<(), Error> {
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
        return Err(Error::new(ErrorKind::Unsupported, "file hash does not match"))
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

fn build_argon2_salt() -> [u8; 16] {
    let mut result = [0u8; 16];
    OsRng.fill_bytes(&mut result);
    result
}

fn build_chacha_salt() -> [u8; 12] {
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
        let actions = db.save(file_name)?;
        assert_eq!(actions.len(), 3);
        let mut db2 = PmanDatabaseFile::prepare(actions[0].get_data())?;
        let file_names = db2.pre_open(hash1_vec, hash2_vec)?;
        assert_eq!(actions.len(), 2);
        db2.open(vec![actions[1].get_data(), actions[2].get_data()])
    }
}