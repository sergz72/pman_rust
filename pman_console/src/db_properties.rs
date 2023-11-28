use std::io::{Error, ErrorKind};
use pman_lib::set_argon2;
use crate::Parameters;
use crate::utils::load_file;

pub fn set_file1_location(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    match parameters.passwords_file_parameter.get_value().as_str() {
        "qs3" => {
            let qs3_path = parameters.qs3_path_parameter2.get_value();
            let qs3_key = parameters.qs3_key_parameter2.get_value();
            if qs3_path.is_empty() || qs3_key.is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "qs3-path2 & qs3-key2 must be provided"));
            }
            pman_lib::set_file1_location_qs3(database, qs3_path, load_file(qs3_key)?)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            Ok(true)
        },
        _ => Err(Error::new(ErrorKind::InvalidInput, "invalid passwords file location"))
    }
}

pub fn set_file2_location(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    match parameters.names_file_parameter.get_value().as_str() {
        "qs3" => {
            let qs3_path = parameters.qs3_path_parameter1.get_value();
            let qs3_key = parameters.qs3_key_parameter1.get_value();
            if qs3_path.is_empty() || qs3_key.is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "qs3-path1 & qs3-key1 must be provided"));
            }
            pman_lib::set_file2_location_qs3(database, qs3_path, load_file(qs3_key)?)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            Ok(true)
        },
        _ => Err(Error::new(ErrorKind::InvalidInput, "invalid names file location"))
    }
}

pub fn set_hash2(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    set_hash(database, 1, parameters.hash2_parameter.get_value(),
             parameters.iterations2_parameter.get_value(),
             parameters.memory2_parameter.get_value(),
             parameters.parallelism2_parameter.get_value())?;
    Ok(true)
}

pub fn set_hash1(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    set_hash(database, 0, parameters.hash_parameter.get_value(),
             parameters.iterations_parameter.get_value(),
             parameters.memory_parameter.get_value(),
             parameters.parallelism_parameter.get_value())?;
    Ok(true)
}

fn set_hash(database: u64, hash_id: u64, hash_type: String, iterations: isize, memory: isize,
            parallelism: isize) -> Result<(), Error> {
    match hash_type.as_str() {
        "argon2" => set_argon2(database, hash_id, iterations as u64,
                               parallelism as u64, memory as u64)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string())),
        _ => Err(Error::new(ErrorKind::InvalidInput, "unknown hash type"))
    }
}

