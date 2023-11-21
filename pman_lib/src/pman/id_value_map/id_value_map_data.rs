/*
fn build_encryption_processor(algorithm: u8, encryption_key: [u8; 32]) -> Result<(Arc<dyn CryptoProcessor>, Vec<u8>), Error> {
    let mut algorithm_parameters = vec![algorithm];
    match algorithm {
        ENCRYPTION_ALGORITHM_AES => {
            let processor = build_aes_processor(algorithm_parameters, encryption_key)?;
            Ok((processor, Vec::new()))
        },
        ENCRYPTION_ALGORITHM_CHACHA20 => {
            let salt = build_chacha_salt();
            algorithm_parameters.extend_from_slice(&salt);
            let processor = build_chacha_processor(algorithm_parameters, encryption_key)?;
            Ok((processor, Vec::from(salt)))
        },
        _ => Err(build_unsupported_algorithm_error())
    }
}


fn new_data_file_handlers(file_info: &mut IdValueMap) -> Result<Vec<Box<dyn IdValueMapDataHandler + Send + Sync>>, Error> {
    let locations: Vec<u8> = file_info.get(FILES_LOCATIONS_ID)?;
    let mut result: Vec<Box<dyn IdValueMapDataHandler + Send + Sync>> = Vec::new();
    for location in locations {
        let location_data: Vec<u8> = file_info.get(location as u32)?;
        if location_data.is_empty() {
            return Err(build_corrupted_data_error(" new_data_file_handlers1"));
        }
        match location_data[0] {
            FILE_LOCATION_LOCAL => {
                if location_data.len() != 1 {
                    return Err(build_corrupted_data_error(" new_data_file_handlers2"));
                }
                result.push(Box::new(IdValueMapDataFileHandler::new()))
            },
            FILE_LOCATION_S3 => {
                let handler = IdValueMapS3Handler::new(location_data[1..].to_vec())?;
                result.push(Box::new(handler));
            },
            _ => return Err(build_corrupted_data_error(" new_data_file_handlers3"))
        }
    }
    Ok(result)
}

fn build_data_file_handlers(file_info: &mut IdValueMap, local_file_data: Option<Vec<u8>>,
                            encryption_key: [u8; 32], alg1: u8) -> Result<Vec<Box<dyn IdValueMapDataHandler + Send + Sync>>, Error> {
    let locations: Vec<u8> = file_info.get(FILES_LOCATIONS_ID)?;
    let mut result: Vec<Box<dyn IdValueMapDataHandler + Send + Sync>> = Vec::new();
    for location in locations {
        let location_data: Vec<u8> = file_info.get(location as u32)?;
        if location_data.is_empty() {
            return Err(build_corrupted_data_error("build_data_file_handlers1"));
        }
        match location_data[0] {
            FILE_LOCATION_LOCAL => {
                if local_file_data.is_none() {
                    return Err(build_corrupted_data_error("build_data_file_handlers2"));
                }
                let handler =
                    IdValueMapDataFileHandler::load(local_file_data.clone().unwrap(), encryption_key, alg1)?;
                result.push(Box::new(handler));
            },
            FILE_LOCATION_S3 => {
                let handler = IdValueMapS3Handler::load(location_data[1..].to_vec(), encryption_key, alg1)?;
                result.push(Box::new(handler));
            },
            _ => return Err(build_corrupted_data_error("build_data_file_handlers3"))
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::AesProcessor;
    use crate::pman::id_value_map::id_value_map_data::IdValueMapData;
    use crate::pman::pman_database_file::{build_argon2_salt, build_chacha_salt, ENCRYPTION_ALGORITHM_CHACHA20};

    #[test]
    fn test_id_value_map_data() -> Result<(), Error> {
        let mut encryption_key = [0u8; 32];
        OsRng.fill_bytes(&mut encryption_key);
        let processor= AesProcessor::new(encryption_key);
        let d1 = Vec::from(build_chacha_salt());
        let data1 = processor.encode(d1.clone())?;
        let d2 = Vec::from(build_argon2_salt());
        let data2 = processor.encode(d2.clone())?;
        let map_data = IdValueMapData::new(processor)?;
        let map: HashMap<u32, Option<IdValueMapValue>> = HashMap::from([
            (1, Some(IdValueMapValue{ updated: false, data: data1})),
            (2, Some(IdValueMapValue{ updated: false, data: data2}))
        ]);
        let handler = IdValueMapDataFileHandler::new();
        let (_map, data_option) = handler.save(3, &map,
                                               processor.clone(), processor.clone(),
                                               Some(ENCRYPTION_ALGORITHM_CHACHA20),
                                               Some(encryption_key))?;
        let mut handler2 =
            IdValueMapDataFileHandler::load(data_option.unwrap(), encryption_key,
                                            ENCRYPTION_ALGORITHM_CHACHA20)?;
        assert_eq!(handler2.get_next_id(), 3);
        let map = handler2.get_map()?;
        assert_eq!(map.len(), 2);
        let item1 = map.get(&1).unwrap();
        let d11 = processor.decode(item1)?;
        assert_eq!(d11, d1);
        let item2 = map.get(&2).unwrap();
        let d12 = processor.decode(item2)?;
        assert_eq!(d12, d2);
        Ok(())
    }
}
*/