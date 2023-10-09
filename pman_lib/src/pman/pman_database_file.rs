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
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crate::crypto::{AesProcessor, build_corrupted_data_error, ChachaProcessor, CryptoProcessor, NoEncryptionProcessor};
use crate::pman::id_value_map::IdValueMap;
use crate::pman::ids::{DATABASE_VERSION_ID, ENCRYPTION_ALGORITHM1_PROPERTIES_ID,
                       ENCRYPTION_ALGORITHM2_PROPERTIES_ID, HASH_ALGORITHM_PROPERTIES_ID};
use crate::pman::names_file::NamesFile;
use crate::pman::passwords_file::PasswordsFile;

const DATABASE_VERSION_MIN: u16 = 0x100; // 1.0
const DATABASE_VERSION_MAX: u16 = 0x100; // 1.0
const DATABASE_VERSION_1: u16 = 0x100; // 1.0
pub const HASH_ALGORITHM_ARGON2: u8 = 1;
pub const DEFAULT_ARGON2_ITERATIONS: u8 = 10;
pub const DEFAULT_ARGON2_MEMORY: u16 = 128;
pub const DEFAULT_ARGON2_PARALLELISM: u8 = 6;
pub const ENCRYPTION_ALGORITHM_AES: u8 = 1;
pub const ENCRYPTION_ALGORITHM_CHACHA20: u8 = 2;
pub const FILE_LOCATION_LOCAL: u8 = 1;

struct PmanDatabaseFile {
    password_hash: Vec<u8>,
    password2_hash: Vec<u8>,
    encryption_key: [u8; 32],
    encryption2_key: [u8; 32],
    header: IdValueMap<Vec<u8>>,
    names_file: NamesFile,
    passwords_file: PasswordsFile,
}

type HmacSha256 = Hmac<Sha256>;

impl PmanDatabaseFile {
    fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseFile, Error> {
        let mut h = IdValueMap::new(NoEncryptionProcessor::new());
        h.add_with_id(DATABASE_VERSION_ID, DATABASE_VERSION_1.to_le_bytes().to_vec()).unwrap();
        h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();

        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let encryption_key = build_encryption_key(&h, &password_hash)?;
        let processor12 = build_encryption_processor(alg2, encryption_key)?;
        let names_file = NamesFile::new(processor12);

        let (alg21, alg22) = get_encryption_algorithms(&h)?;
        let encryption2_key = build_encryption_key(&h, &password2_hash)?;
        let processor22 = build_encryption_processor(alg22, encryption_key)?;
        let passwords_file = PasswordsFile::new(processor22);

        Ok(PmanDatabaseFile{
            password_hash,
            password2_hash,
            encryption_key,
            encryption2_key,
            header: h,
            names_file,
            passwords_file,
        })
    }

    fn open(mut data: Vec<u8>, password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseFile, Error> {
        let l = validate_data_hash(&data)?;
        let mut h: IdValueMap<Vec<u8>> = IdValueMap::new(NoEncryptionProcessor::new());
        let offset = h.load(&data, 0)?;
        let _v = validate_database_version(&h)?;
        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let a1 = alg1[0];
        let encryption_key = build_encryption_key(&h, &password_hash)?;
        let l2 = validate_data_hmac(&encryption_key, &data, l)?;
        let processor11 = build_encryption_processor(alg1, encryption_key)?;
        decrypt_data(processor11.clone(), &mut data, offset, l2)?;

        let processor12 = build_encryption_processor(alg2, encryption_key)?;
        let mut names_files_info: IdValueMap<Vec<u8>> = IdValueMap::new(processor12.clone());
        let offset2 = names_files_info.load(&data, offset)?;

        let (alg21, alg22) = get_encryption_algorithms(&names_files_info)?;
        let a2 = alg21[0];
        let encryption2_key = build_encryption_key(&names_files_info, &password2_hash)?;
        let processor21 = build_encryption_processor(alg21, encryption2_key)?;
        decrypt_data(processor21.clone(), &mut data, offset2, l2)?;
        let processor22 = build_encryption_processor(alg22, encryption2_key)?;
        let mut passwords_files_info: IdValueMap<Vec<u8>> = IdValueMap::new(processor22.clone());
        let offset3 = passwords_files_info.load(&data, offset2)?;

        if offset3 != l2 {
            return Err(build_corrupted_data_error());
        }

        let names_file = NamesFile::load(encryption_key, a1, processor12, names_files_info)?;
        let passwords_file = PasswordsFile::load(encryption2_key, a2, processor22, passwords_files_info)?;

        let db = PmanDatabaseFile{
            password_hash,
            password2_hash,
            encryption_key,
            encryption2_key,
            header: h,
            names_file,
            passwords_file,
        };
        Ok(db)
    }

    fn save(&mut self) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        modify_algorithm_properties(&self.header);
        self.header.save(&mut output);
        let offset = output.len();
        let encryption_key = build_encryption_key(&self.header, &self.password_hash)?;
        //self.names_file.save(&mut output, &encryption_key);
        let (alg1, alg2) = get_encryption_algorithms(&self.header)?;
        //encrypt_data(alg1, &encryption_key, output, offset, output.len());
        add_data_hash_and_hmac(&mut output, encryption_key)?;
        Ok(output)
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

pub fn modify_algorithm_properties(header: &IdValueMap<Vec<u8>>) {
    todo!()
}

fn encrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    processor.encode_bytes(&mut data[offset..offset+length])
}

pub fn decrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    processor.decode_bytes(&mut data[offset..offset+length])
}

pub fn get_encryption_algorithms(header: &IdValueMap<Vec<u8>>) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let alg1 = header.get(ENCRYPTION_ALGORITHM1_PROPERTIES_ID)?;
    let alg2 = header.get(ENCRYPTION_ALGORITHM2_PROPERTIES_ID)?;
    return Ok((alg1, alg2))
}

pub fn build_encryption_key(header: &IdValueMap<Vec<u8>>, password_hash: &Vec<u8>) -> Result<[u8;32], Error> {
    todo!()
}

fn validate_database_version(header: &IdValueMap<Vec<u8>>) -> Result<usize, Error> {
    let version_bytes = header.get(DATABASE_VERSION_ID)?;
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

fn default_aes_properties() -> Vec<u8> {
    vec![ENCRYPTION_ALGORITHM_AES]
}

fn default_chacha_properties() -> Vec<u8> {
    let mut result = vec![ENCRYPTION_ALGORITHM_CHACHA20];
    result.extend_from_slice(&build_chacha_salt());
    result
}

fn default_argon2_properties() -> Vec<u8> {
    build_argon2_properties(DEFAULT_ARGON2_ITERATIONS,
                            DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_MEMORY,
                        build_argon2_salt())
}

fn build_argon2_properties(iterations: u8, parallelism: u8, memory: u16, salt: [u8; 16]) -> Vec<u8> {
    let mut result = vec![HASH_ALGORITHM_ARGON2, iterations, parallelism];
    result.extend_from_slice(&memory.to_le_bytes());
    result.extend_from_slice(&salt);
    result
}

fn set_argon2_salt(input: &mut Vec<u8>, salt: [u8; 16]) {
    input[5..21].copy_from_slice(&salt);
}
fn set_chacha_salt(input: &mut Vec<u8>, salt: [u8; 12]) {
    input[1..13].copy_from_slice(&salt);
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
    use crate::pman::pman_database_file::{add_data_hash_and_hmac, validate_data_hash, validate_data_hmac};

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