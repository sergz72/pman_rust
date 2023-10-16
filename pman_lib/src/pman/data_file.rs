use std::io::Error;
use std::sync::Arc;
use crate::crypto::{build_corrupted_data_error, CryptoProcessor};
use crate::pman::id_value_map::id_value_map::{IdValueMap, IdValueMapDataHandler};
use crate::pman::id_value_map::id_value_map_local_data_handler::IdValueMapLocalDataHandler;
use crate::pman::ids::{ENCRYPTION_ALGORITHM1_PROPERTIES_ID, ENCRYPTION_ALGORITHM2_PROPERTIES_ID, FILES_LOCATIONS_ID, HASH_ALGORITHM_PROPERTIES_ID};
use crate::pman::pman_database_file::{decrypt_data, default_aes_properties, default_argon2_properties, default_chacha_properties, FILE_LOCATION_LOCAL, validate_data_hash, validate_data_hmac};
use crate::structs_interfaces::FileAction;

pub struct DataFile {
    data: IdValueMap
}

impl DataFile {
    pub fn new(file_info: &IdValueMap, encryption_key: [u8; 32], alg1: u8, processor2: Arc<dyn CryptoProcessor>) -> Result<DataFile, Error> {
        let handler = build_data_file_handler(file_info, None, encryption_key, alg1)?;
        Ok(DataFile {data: IdValueMap::new(processor2, handler)?})
    }

    pub fn pre_load(main_file_name: &String, file_info: &IdValueMap) -> Result<Option<String>, Error> {
        build_local_file_name(main_file_name, file_info)
    }

    pub fn load(local_file_data: Option<Vec<u8>>, file_info: &IdValueMap, encryption_key: [u8; 32], alg1: u8, processor2: Arc<dyn CryptoProcessor>) -> Result<DataFile, Error> {
        let handler = build_data_file_handler(file_info, local_file_data, encryption_key, alg1)?;
        Ok(DataFile {data: IdValueMap::new(processor2, handler)?})
/*        let l = validate_data_hash(&data)?;
        let l2 = validate_data_hmac(&encryption_key, &data, l)?;
        let (processor1, offset) = load_encryption_processor(alg1, encryption_key, &data)?;
        decrypt_data(processor1, &mut data, offset, l2)?;
        let mut entities: IdValueMap = IdValueMap::new(processor2.clone());
        let offset2 = entities.load(&data, offset)?;
        let mut names: IdValueMap = IdValueMap::new(processor2);
        let offset3 = names.load(&data, offset2)?;
        if offset3 != l2 {
            return Err(build_corrupted_data_error());
        }
        Ok(DataFile {
            entities,
            names,
        })*/
    }

    pub fn save(&self, file_name: String, encryption_key: [u8; 32], alg1: u8,
                processor2: Arc<dyn CryptoProcessor>,
                file_info: &IdValueMap) -> Result<Option<FileAction>, Error> {
        let mut data = Vec::new();
        save_to_destinations(file_info, file_name, data)
    }

    pub fn build_file_info(processor2: Arc<dyn CryptoProcessor>, only_locations: bool) -> Result<IdValueMap, Error> {
        let mut h = IdValueMap::new(processor2, Box::new(IdValueMapLocalDataHandler::new()))?;
        if !only_locations {
            h.add_with_id(HASH_ALGORITHM_PROPERTIES_ID, default_argon2_properties()).unwrap();
            h.add_with_id(ENCRYPTION_ALGORITHM1_PROPERTIES_ID, default_chacha_properties()).unwrap();
            h.add_with_id(ENCRYPTION_ALGORITHM2_PROPERTIES_ID, default_aes_properties()).unwrap();
        }
        h.add_with_id(FILES_LOCATIONS_ID, vec![FILES_LOCATIONS_ID as u8 + 1]).unwrap();
        h.add_with_id(FILES_LOCATIONS_ID+1, build_local_file_location()).unwrap();
        Ok(h)
    }
}

fn build_local_file_name(main_file_name: &String, file_info: &IdValueMap) -> Result<Option<String>, Error> {
    todo!()
}

fn build_data_file_handler(file_info: &IdValueMap, local_file_data: Option<Vec<u8>>,
                           encryption_key: [u8; 32], alg1: u8) -> Result<Box<dyn IdValueMapDataHandler>, Error> {
    todo!()
}

fn save_to_destinations(header: &IdValueMap, file_name: String, data: Vec<u8>) -> Result<Option<FileAction>, Error> {
    todo!()
}

pub fn build_local_file_location() -> Vec<u8> {
    vec![FILE_LOCATION_LOCAL]
}

pub fn load_encryption_processor(alg1: u8, encryption_key: [u8; 32], data: &Vec<u8>) -> Result<(Arc<dyn CryptoProcessor>, usize), Error> {
    todo!()
}
