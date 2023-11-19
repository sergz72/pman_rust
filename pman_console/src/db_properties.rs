use std::io::{Error, ErrorKind};
use pman_lib::set_argon2;
use crate::Parameters;
use crate::utils::load_file;

pub fn set_passwords_file_location(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    match parameters.passwords_file_parameter.get_value().as_str() {
        "local" => pman_lib::set_passwords_file_location_local(database)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string())),
        "s3" => {
            let s3_path = parameters.s3_path_parameter2.get_value();
            let s3_key = parameters.s3_key_parameter2.get_value();
            if s3_path.is_empty() || s3_key.is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "s3-path2 & s3-key2 must be provided"));
            }
            pman_lib::set_passwords_file_location_s3(database, s3_path, load_file(s3_key)?)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
        },
        _ => Err(Error::new(ErrorKind::InvalidInput, "invalid passwords file location"))
    }
}

pub fn set_names_file_location(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    match parameters.names_file_parameter.get_value().as_str() {
        "local" => pman_lib::set_names_file_location_local(database)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string())),
        "s3" => {
            let s3_path = parameters.s3_path_parameter1.get_value();
            let s3_key = parameters.s3_key_parameter1.get_value();
            if s3_path.is_empty() || s3_key.is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "s3-path1 & s3-key1 must be provided"));
            }
            pman_lib::set_names_file_location_s3(database, s3_path, load_file(s3_key)?)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
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

