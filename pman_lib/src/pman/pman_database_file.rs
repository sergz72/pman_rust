/*
database file structure
    header -> id_value_map
        database version
        names_file_hash_algorithm properties
        names_file_encryption_algorithm properties
        names_file_location
    entities -> id_value_map
    // encrypted //
    names_file -> see below
    // not encrypted //
    sha512 for file data

names file structure
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

use crate::pman::entity_map::EntityMap;
use crate::pman::id_value_map::IdValueMap;
use crate::pman::names_file::NamesFile;

struct PmanDatabaseFile {
    header: IdValueMap<String>,
    entities: IdValueMap<HeaderEntity>,
    names_file: NamesFile
}

impl PmanDatabaseFile {
    fn save(output: &mut Vec<u8>) {

    }
}