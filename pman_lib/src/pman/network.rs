use std::io::{Error, ErrorKind};
use s3cli_lib::KeyInfo;
use crate::error_builders::build_corrupted_data_error;
use crate::pman::pman_database_file::FILE_LOCATION_QS3;
use s3cli_lib::qs3::QKeyInfo;

pub trait NetworkFileHandler {
    fn download(&self) -> Result<Vec<u8>, Error>;
    fn upload(&self, data: Vec<u8>) -> Result<(), Error>;
}

pub struct QS3Handler {
    key_info: QKeyInfo,
    path: String
}

impl NetworkFileHandler for QS3Handler {
    fn download(&self) -> Result<Vec<u8>, Error> {
        let request_info =
            self.key_info.build_request_info("GET", chrono::Utc::now(), &Vec::new(), &self.path)?;
        request_info.make_request(None)
    }

    fn upload(&self, data: Vec<u8>) -> Result<(), Error> {
        let request_info =
            self.key_info.build_request_info("PUT", chrono::Utc::now(), &Vec::new(), &self.path)?;
        let _ = request_info.make_request(Some(data))?;
        Ok(())
    }
}

impl QS3Handler {
    pub fn new(location_data: Vec<u8>, rsa_key: String) -> Result<QS3Handler, Error> {
        let (path, key_data) = decode_location_data(location_data)?;
        let key_info = QKeyInfo::new(key_data, rsa_key, 2, 3)?;
        Ok(QS3Handler{ key_info, path })
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
    Ok((path, location_data[l+1..].to_vec()))
}

fn build_file_handler(location_data: Vec<u8>, rsa_key: &String)
    -> Result<Box<dyn NetworkFileHandler>, Error> {
    if location_data.is_empty() {
        return Err(build_corrupted_data_error("build_file_handler1"));
    }
    match location_data[0] {
        FILE_LOCATION_QS3 => {
            let handler = QS3Handler::new(location_data[1..].to_vec(), rsa_key.clone())?;
            Ok(Box::new(handler))
        },
        _ => Err(build_corrupted_data_error(" new_data_file_handlers3"))
    }
}

pub fn download_file(rsa_key: &String, location_data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let handler = build_file_handler(location_data, rsa_key)?;
    handler.download()
}

pub fn upload_file(rsa_key: &String, data: Vec<u8>, location_data: Vec<u8>) -> Result<(), Error> {
    let handler = build_file_handler(location_data, rsa_key)?;
    handler.upload(data)
}