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
use rand::RngCore;
use rand::rngs::OsRng;
use crate::crypto::{build_corrupted_data_error, CryptoProcessor, NoEncryptionProcessor};
use crate::pman::id_value_map::IdValueMap;
use crate::pman::ids::{DATABASE_VERSION_ID, ENCRYPTION_ALGORITHM1_PROPERTIES_ID,
                       ENCRYPTION_ALGORITHM2_PROPERTIES_ID, HASH_ALGORITHM_PROPERTIES_ID};
use crate::pman::names_file::NamesFile;
use crate::pman::passwords_file::PasswordsFile;
use crate::structs_interfaces::{DownloadAction, UploadAction};

const DATABASE_VERSION: u16 = 0x100; // 1.0
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
    alg1: u8,
    alg2: u8,
    processor12: Option<Arc<dyn CryptoProcessor>>,
    processor22: Option<Arc<dyn CryptoProcessor>>,
    header: IdValueMap<Vec<u8>>,
    names_file: Option<NamesFile>,
    passwords_file: Option<PasswordsFile>,
    pre_save_result: Option<Vec<u8>>
}

impl PmanDatabaseFile {
    fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseFile, Error> {
        let mut h = IdValueMap::new(NoEncryptionProcessor::new());
        h.add_with_id(DATABASE_VERSION_ID, DATABASE_VERSION.to_le_bytes().to_vec()).unwrap();
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
            alg1: alg1[0],
            alg2: alg21[0],
            processor12: None,
            processor22: None,
            header: h,
            names_file: Some(names_file),
            passwords_file: Some(passwords_file),
            pre_save_result: None
        })
    }

    fn pre_open(data: Vec<u8>, password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<(PmanDatabaseFile, Vec<DownloadAction>), Error> {
        let l = validate_data_hash(&data)?;
        let mut h: IdValueMap<Vec<u8>> = IdValueMap::new(NoEncryptionProcessor::new());
        let offset = h.load(&data, 0)?;
        let _v = validate_database_version(&h)?;
        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let encryption_key = build_encryption_key(&h, &password_hash)?;
        let l2 = validate_data_hmac(&encryption_key, &data, l)?;
        let processor11 = build_encryption_processor(alg1, encryption_key)?;
        decrypt_data(processor11.clone(), &data, offset, l2);

        let processor12 = build_encryption_processor(alg2, encryption_key)?;
        let mut names_files_info: IdValueMap<Vec<u8>> = IdValueMap::new(processor12.clone());
        let offset2 = names_files_info.load(&data, offset)?;

        let (alg21, alg22) = get_encryption_algorithms(&names_files_info)?;
        let encryption2_key = build_encryption_key(&names_files_info, &password2_hash)?;
        let processor21 = build_encryption_processor(alg21, encryption2_key)?;
        decrypt_data(processor21.clone(), &data, offset2, l2);
        let processor22 = build_encryption_processor(alg22, encryption2_key)?;
        let mut passwords_files_info: IdValueMap<Vec<u8>> = IdValueMap::new(processor22.clone());
        let offset3 = passwords_files_info.load(&data, offset2)?;

        if offset3 != l2 {
            return Err(build_corrupted_data_error());
        }

        let command = build_download_command(names_files_info)?;
        let command2 = build_download_command(passwords_files_info)?;
        let commands = vec![command, command2];

        let db = PmanDatabaseFile{
            password_hash,
            password2_hash,
            encryption_key,
            encryption2_key,
            alg1: alg1[0],
            alg2: alg21[0],
            processor12: Some(processor12),
            processor22: Some(processor22),
            header: h,
            names_file: None,
            passwords_file: None,
            pre_save_result: None
        };
        Ok((db, commands))
    }

    fn open(&mut self, mut download_result: Vec<Vec<u8>>) -> Result<(), Error> {
        if self.processor12.is_none() || self.processor22.is_none() || self.names_file.is_some() ||
            self.passwords_file.is_some() {
            return Err(Error::new(ErrorKind::InvalidInput, "database must be in pre-open state"));
        }
        if download_result.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, "download_result length should be 2"));
        }
        let result2 = download_result.remove(1);
        let result1 = download_result.remove(0);
        self.names_file = Some(NamesFile::load(self.encryption_key, self.alg1, self.processor12.unwrap(), result1)?);
        self.passwords_file = Some(PasswordsFile::load(self.encryption2_key, self.alg2, self.processor22.unwrap(), result2)?);
        Ok(())
    }

    fn pre_save(&mut self) -> Result<Vec<UploadAction>, Error> {
        let mut output = Vec::new();
        modify_algorithm_properties(&self.header);
        self.header.save(&mut output);
        let offset = output.len();
        let encryption_key = build_encryption_key(&self.header, &self.password_hash)?;
        self.names_file.save(&mut output, &encryption_key);
        let (alg1, alg2) = get_encryption_algorithms(&self.header)?;
        encrypt_data(alg1, &encryption_key, output, offset, output.len());
        add_data_hash_and_hmac(&mut output, encryption_key);
        self.pre_save_result = Some(output);
        Ok(())
    }

    fn save(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.pre_save_result.unwrap())
    }
}

fn build_download_command(file_info: IdValueMap<Vec<u8>>) -> Result<DownloadAction, Error> {
    todo!()
}

fn build_encryption_processor(algorithm_parameters: Vec<u8>, encryption_key: [u8; 32]) -> Result<Arc<dyn CryptoProcessor>, Error> {
    todo!()
}

pub fn modify_algorithm_properties(header: &IdValueMap<Vec<u8>>) {
    todo!()
}

fn encrypt_data(processor: Arc<dyn CryptoProcessor>, data: &mut Vec<u8>, offset: usize, length: usize) {
    todo!()
}

pub fn decrypt_data(processor: Arc<dyn CryptoProcessor>, data: &Vec<u8>, offset: usize, length: usize) {
    todo!()
}

pub fn get_encryption_algorithms(header: &IdValueMap<Vec<u8>>) -> Result<(Vec<u8>, Vec<u8>), Error> {
    todo!()
}

pub fn validate_data_hmac(encryption_key: &[u8; 32], data: &Vec<u8>, length: usize) -> Result<usize, Error> {
    todo!()
}

pub fn build_encryption_key(header: &IdValueMap<Vec<u8>>, password_hash: &Vec<u8>) -> Result<[u8;32], Error> {
    todo!()
}

fn validate_database_version(header: &IdValueMap<Vec<u8>>) -> Result<usize, Error> {
    todo!()
}

// validate data using sha512
fn add_data_hash_and_hmac(data: &mut Vec<u8>, encryption_key: [u8; 32]) {
    todo!()
}

pub fn validate_data_hash(data: &Vec<u8>) -> Result<usize, Error> {
    todo!()
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