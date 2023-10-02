/*
database file structure
    header -> id_value_map
        database version
        names_file_hash_algorithm properties
        names_file_encryption_algorithm properties
        names_file_location
    // encrypted //
    names_file -> see below
    // not encrypted //
    sha512 for file data

names file structure
    entities -> id_value_map
    header -> id_value_map
        passwords_file_hash_algorithm properties
        passwords_file_encryption_algorithm properties
        passwords_file_location
    names_map -> id_value_map
    // encrypted //
    passwords_file -> see below
    // not encrypted //
    sha512 for file data

passwords file structure
    passwords_map -> id_value_map
    sha512 for file data
*/

use std::io::Error;
use rand::RngCore;
use rand::rngs::OsRng;
use crate::crypto::NoEncryptionProcessor;
use crate::pman::id_value_map::IdValueMap;
use crate::pman::ids::{DATABASE_VERSION_ID, ENCRYPTION_ALGORITHM1_PROPERTIES_ID,
                       ENCRYPTION_ALGORITHM2_PROPERTIES_ID, HASH_ALGORITHM_PROPERTIES_ID,
                       NAMES_FILES_LOCATIONS_ID};
use crate::pman::names_file::NamesFile;
use crate::pman::passwords_file::PasswordsFile;

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
    header: IdValueMap<Vec<u8>>,
    names_file: NamesFile,
    passwords_file: PasswordsFile
}

impl PmanDatabaseFile {
    fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> PmanDatabaseFile {
        let mut h = IdValueMap::new(NoEncryptionProcessor::new());
        h.add_with_id(DATABASE_VERSION_ID, DATABASE_VERSION.to_le_bytes().to_vec()).unwrap();
        h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();
        PmanDatabaseFile{password_hash, header: h, names_file: NamesFile::new(processor1, processor2)}
    }

    fn open(data: Vec<u8>, password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<PmanDatabaseFile, Error> {
        let l = validate_data_hash(&data, 0, data.len())?;
        let mut h: IdValueMap<Vec<u8>> = IdValueMap::new(NoEncryptionProcessor::new());
        let offset = h.load(&data, 0)?;
        let _v = validate_database_version(&h)?;
        let (alg1, alg2) = get_encryption_algorithms(&h)?;
        let encryption_key = build_encryption_key(&h, &password_hash)?;
        let l2 = validate_data_hmac(&encryption_key, &data, 0, l)?;
        decrypt_data(alg1, &encryption_key, &data, offset, l2);
        let (names_file, passwords_file) = NamesFile::load(alg2, encryption_key,
                                         password2_hash, data, offset, l2)?;
        let db = PmanDatabaseFile{password_hash, header: h, names_file, passwords_file};
        Ok(db)
    }

    fn save(&mut self, output: &mut Vec<u8>) -> Result<(), Error> {
        modify_algorithm_properties(&self.header);
        let encryption_key = build_encryption_key(&self.header, &self.password_hash)?;
        self.header.save(output);
        let offset = output.len();
        self.names_file.save(output, &encryption_key);
        let (alg1, alg2) = get_encryption_algorithms(&self.header)?;
        encrypt_data(alg1, &encryption_key, output, offset, output.len());
        add_data_hmac(output, encryption_key);
        add_data_hash(output);
        Ok(())
    }
}

pub fn modify_algorithm_properties(header: &IdValueMap<Vec<u8>>) {
    todo!()
}

fn encrypt_data(algorithm_parameters: Vec<u8>, encryption_key: &[u8; 32], data: &mut Vec<u8>, offset: usize, length: usize) {
    todo!()
}

pub fn decrypt_data(algorithm_parameters: Vec<u8>, encryption_key: &[u8; 32], data: &Vec<u8>, offset: usize, length: usize) {
    todo!()
}

pub fn get_encryption_algorithms(header: &IdValueMap<Vec<u8>>) -> Result<(Vec<u8>, Vec<u8>), Error> {
    todo!()
}

fn add_data_hmac(output: &mut Vec<u8>, encryption_key: [u8; 32]) {
    todo!()
}

pub fn validate_data_hmac(encryption_key: &[u8; 32], data: &Vec<u8>, offset: usize, length: usize) -> Result<usize, Error> {
    todo!()
}

pub fn build_encryption_key(header: &IdValueMap<Vec<u8>>, password_hash: &Vec<u8>) -> Result<[u8;32], Error> {
    todo!()
}

fn validate_database_version(header: &IdValueMap<Vec<u8>>) -> Result<usize, Error> {
    todo!()
}

// validate data using sha512
fn add_data_hash(data: &mut Vec<u8>) {
    todo!()
}

pub fn validate_data_hash(data: &Vec<u8>, offset: usize, length: usize) -> Result<usize, Error> {
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