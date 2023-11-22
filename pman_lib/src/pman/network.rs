use std::io::{Error, ErrorKind};
use crate::error_builders::build_corrupted_data_error;
use crate::pman::pman_database_file::FILE_LOCATION_QS3;

trait NetworkFileHandler {
    fn download(&self) -> Result<Vec<u8>, Error>;
    fn upload(&self, data: Vec<u8>) -> Result<(), Error>;
}

struct QS3Handler {

}

impl NetworkFileHandler for QS3Handler {
    fn download(&self) -> Result<Vec<u8>, Error> {
        todo!()
    }

    fn upload(&self, data: Vec<u8>) -> Result<(), Error> {
        todo!()
    }
}

impl QS3Handler {
    fn new(location_data: Vec<u8>) -> Result<QS3Handler, Error> {
        let (path, key_data) = decode_location_data(location_data)?;
        todo!()
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

fn build_file_handler(location_data: Vec<u8>) -> Result<Box<dyn NetworkFileHandler>, Error> {
    if location_data.is_empty() {
        return Err(build_corrupted_data_error("build_file_handler1"));
    }
    match location_data[0] {
        FILE_LOCATION_QS3 => {
            let handler = QS3Handler::new(location_data[1..].to_vec())?;
            Ok(Box::new(handler))
        },
        _ => Err(build_corrupted_data_error(" new_data_file_handlers3"))
    }
}
pub fn download_file(location_data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let handler = build_file_handler(location_data)?;
    handler.download()
}

pub fn upload_file(data: Vec<u8>, location_data: Vec<u8>) -> Result<(), Error> {
    let handler = build_file_handler(location_data)?;
    handler.upload(data)
}