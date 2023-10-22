use std::io::{Error, ErrorKind};

pub fn build_unsupported_error() -> Error {
    Error::new(ErrorKind::Unsupported, "unsupported")
}

pub fn build_not_found_error() -> Error {
    Error::new(ErrorKind::NotFound, "not found")
}

pub fn build_corrupted_data_error() -> Error {
    Error::new(ErrorKind::InvalidData, "corrupted data")
}

pub fn build_read_only_db_error() -> Error {
    Error::new(ErrorKind::Unsupported, "database is read only")
}