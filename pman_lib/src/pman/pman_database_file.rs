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

use std::sync::Arc;
use rand::RngCore;
use rand::rngs::OsRng;
use crate::crypto::{CryptoProcessor, NoEncryptionProcessor};
use crate::pman::id_value_map::IdValueMap;
use crate::pman::ids::{DATABASE_VERSION_ID, ENCRYPTION_ALGORITHM_PROPERTIES_ID, HASH_ALGORITHM_PROPERTIES_ID};
use crate::pman::names_file::NamesFile;

const DATABASE_VERSION: u16 = 0x100; // 1.0
pub const HASH_ALGORITHM_ARGON2: u8 = 1;
pub const DEFAULT_ARGON2_ITERATIONS: u8 = 10;
pub const DEFAULT_ARGON2_MEMORY: u16 = 128;
pub const DEFAULT_ARGON2_PARALLELISM: u8 = 6;
pub const ENCRYPTION_ALGORITHM_AES: u8 = 1;

struct PmanDatabaseFile {
    header: IdValueMap<Vec<u8>>,
    names_file: NamesFile
}

impl PmanDatabaseFile {
    fn new(password: String, password2: String) -> PmanDatabaseFile {
        let mut h = IdValueMap::new(NoEncryptionProcessor::new());
        h.add_with_id(DATABASE_VERSION_ID, DATABASE_VERSION.to_le_bytes().to_vec()).unwrap();
        h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
        h.add_with_id(ENCRYPTION_ALGORITHM_PROPERTIES_ID, default_aes_properties()).unwrap();
        PmanDatabaseFile{header: h, names_file: NamesFile::new(processor1, processor2)}
    }

    fn save(output: &mut Vec<u8>) {

    }
}

fn default_aes_properties() -> Vec<u8> {
    vec![ENCRYPTION_ALGORITHM_AES]
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

fn build_argon2_salt() -> [u8; 16] {
    let mut result = [0u8; 16];
    OsRng.fill_bytes(&mut result);
    result
}