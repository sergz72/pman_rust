use std::io::{Error, ErrorKind};
use s3cli_lib::{build_key_info, KeyInfo, S3KeyInfo};
use crate::error_builders::build_corrupted_data_error;
use crate::pman::data_file::data_file::DataFileHandler;

pub struct DataFileQS3Handler {
    key_info: S3KeyInfo,
    path: String
}

impl DataFileHandler for DataFileQS3Handler {
    fn save(&self, data: Vec<u8>) -> Result<(), Error> {
        self.save_to_qs3(data)
    }
}

impl DataFileQS3Handler {
    pub fn save_to_qs3(&self, data: Vec<u8>) -> Result<(), Error> {
        let request_info = self.key_info.build_request_info("PUT",
                                                       chrono::Utc::now(), &data,
                                                            &self.path)?;
        let _ = request_info.make_request(Some(data))?;
        Ok(())
    }

    pub fn load_from_qs3(&self) -> Result<Vec<u8>, Error> {
        load_from_qs3(&self.key_info, &self.path)
    }

    pub fn new(location_data: Vec<u8>) -> Result<DataFileQS3Handler, Error> {
        let (path, key_data) = decode_location_data(location_data)?;
        let key_info = build_key_info(key_data)?;
        Ok(DataFileQS3Handler { key_info, path })
    }
}

fn decode_location_data(location_data: Vec<u8>) -> Result<(String, Vec<u8>), Error> {
    if location_data.is_empty() {
        return Err(build_corrupted_data_error("decode_location_data1"));
    }
    let l = location_data[0] as usize;
    if location_data.len() < l + 2 {
        return Err(build_corrupted_data_error("decode_location_data2"));
    }
    let path = String::from_utf8(location_data[1..=l].to_vec())
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let l2 = location_data[l + 1] as usize;
    if location_data.len() != l + 2 + l2 {
        return Err(build_corrupted_data_error("decode_location_data3"));
    }
    Ok((path, location_data[l+2..].to_vec()))
}

fn load_from_qs3(key_info: &S3KeyInfo, path: &String) -> Result<Vec<u8>, Error> {
    let request_info = key_info.build_request_info("GET",
                                                   chrono::Utc::now(), &Vec::new(), path)?;
    request_info.make_request(None)
}