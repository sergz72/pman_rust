use std::io::Error;
use std::sync::Arc;
use crate::crypto::CryptoProcessor;
use crate::error_builders::build_corrupted_data_error;
use crate::pman::id_value_map::id_value_map::{ByteValue, IdValueMap, IdValueMapDataHandler};
use crate::pman::id_value_map::id_value_map_data_file_handler::IdValueMapDataFileHandler;
use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;
use crate::pman::ids::{ENCRYPTION_ALGORITHM1_PROPERTIES_ID, ENCRYPTION_ALGORITHM2_PROPERTIES_ID, FILES_LOCATIONS_ID, HASH_ALGORITHM_PROPERTIES_ID};
use crate::pman::pman_database_file::{default_aes_properties, default_argon2_properties, default_chacha_properties, FILE_LOCATION_LOCAL};

pub struct DataFile {
    data: IdValueMap
}

impl DataFile {
    pub fn new(file_info: &mut IdValueMap, processor2: Arc<dyn CryptoProcessor>) -> Result<DataFile, Error> {
        let handlers = new_data_file_handlers(file_info)?;
        Ok(DataFile {data: IdValueMap::new(processor2, handlers)?})
    }

    pub fn pre_load(main_file_name: &String, file_extension: &str, file_info: &mut IdValueMap) -> Result<Option<String>, Error> {
        build_local_file_name(main_file_name, file_extension, file_info)
    }

    pub fn load(local_file_data: Option<Vec<u8>>, file_info: &mut IdValueMap, encryption_key: [u8; 32], alg1: u8, processor2: Arc<dyn CryptoProcessor>) -> Result<DataFile, Error> {
        let handlers = build_data_file_handlers(file_info, local_file_data, encryption_key, alg1)?;
        Ok(DataFile {data: IdValueMap::new(processor2, handlers)?})
    }

    pub fn save(&mut self, file_name: String, encryption_key: [u8; 32], alg1: u8,
                processor2: Arc<dyn CryptoProcessor>,
                file_info: &IdValueMap) -> Result<Option<Vec<u8>>, Error> {
        let output = self.data.save(Some(processor2), Some(alg1),
                                    Some(encryption_key))?;
        Ok(output)
    }

    pub fn build_file_info(processor2: Arc<dyn CryptoProcessor>, only_locations: bool) -> Result<IdValueMap, Error> {
        let mut h = IdValueMap::new(processor2, vec![Box::new(IdValueMapLocalDataHandler::new())])?;
        if !only_locations {
            h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
            h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
            h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();
        }
        h.add_with_id(FILES_LOCATIONS_ID, vec![FILES_LOCATIONS_ID as u8 + 1]).unwrap();
        h.add_with_id(FILES_LOCATIONS_ID+1, build_local_file_location()).unwrap();
        Ok(h)
    }

    pub fn get<T: ByteValue>(&mut self, id: u32) -> Result<T, Error> {
        self.data.get(id)
    }
}

fn build_local_file_name(main_file_name: &String, file_exiension: &str,
                         file_info: &mut IdValueMap) -> Result<Option<String>, Error> {
    let locations: Vec<u8> = file_info.get(FILES_LOCATIONS_ID)?;
    for location in locations {
        let location_data: Vec<u8> = file_info.get(location as u32)?;
        if location_data.is_empty() {
            return Err(build_corrupted_data_error());
        }
        if location_data[0] == FILE_LOCATION_LOCAL {
            return Ok(Some(main_file_name.clone() + file_exiension));
        }
    }
    Ok(None)
}

fn new_data_file_handlers(file_info: &mut IdValueMap) -> Result<Vec<Box<dyn IdValueMapDataHandler>>, Error> {
    let locations: Vec<u8> = file_info.get(FILES_LOCATIONS_ID)?;
    let mut result: Vec<Box<dyn IdValueMapDataHandler>> = Vec::new();
    for location in locations {
        let location_data: Vec<u8> = file_info.get(location as u32)?;
        if location_data.is_empty() {
            return Err(build_corrupted_data_error());
        }
        match location_data[0] {
            FILE_LOCATION_LOCAL => {
                if location_data.len() != 1 {
                    return Err(build_corrupted_data_error());
                }
                result.push(Box::new(IdValueMapDataFileHandler::new()))
            },
            _ => return Err(build_corrupted_data_error())
        }
    }
    Ok(result)
}

fn build_data_file_handlers(file_info: &mut IdValueMap, local_file_data: Option<Vec<u8>>,
                            encryption_key: [u8; 32], alg1: u8) -> Result<Vec<Box<dyn IdValueMapDataHandler>>, Error> {
    let locations: Vec<u8> = file_info.get(FILES_LOCATIONS_ID)?;
    let mut result: Vec<Box<dyn IdValueMapDataHandler>> = Vec::new();
    for location in locations {
        let location_data: Vec<u8> = file_info.get(location as u32)?;
        if location_data.is_empty() {
            return Err(build_corrupted_data_error());
        }
        match location_data[0] {
            FILE_LOCATION_LOCAL => {
                if local_file_data.is_none() {
                    return Err(build_corrupted_data_error());
                }
                let handler = IdValueMapDataFileHandler::load(local_file_data.clone().unwrap(), encryption_key, alg1)?;
                result.push(Box::new(handler));
            },
            _ => return Err(build_corrupted_data_error())
        }
    }
    Ok(result)
}

pub fn build_local_file_location() -> Vec<u8> {
    vec![FILE_LOCATION_LOCAL]
}
