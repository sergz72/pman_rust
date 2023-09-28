use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use crate::keepass::keepass_database::KeePassDatabase;
use crate::pman::pman_database::PmanDatabase;
use crate::structs_interfaces::{DownloadAction, PasswordDatabase, PasswordDatabaseType};
use crate::structs_interfaces::CryptoEngine;
use crate::structs_interfaces::HashAlgorithm;

mod structs_interfaces;
mod keepass;
mod pman;
mod aes;

uniffi::include_scaffolding!("pman_lib");

#[derive(Error, Debug)]
pub enum PmanError {
    #[error("Error with message: `{error_text}`")]
    ErrorMessage { error_text: String }
}

impl PmanError {
    pub fn message(msg: impl Into<String>) -> Self {
        Self::ErrorMessage { error_text: msg.into() }
    }
}

struct DatabaseFile {
    file_name: Option<String>,
    database: Arc<RwLock<dyn PasswordDatabase>>
}

static mut DATABASES: Option<HashMap<u64, DatabaseFile>> = None;
static mut NEXT_DB_ID: u64 = 1;

pub fn lib_init() {
    unsafe {
        DATABASES = Some(HashMap::new())
    }
}

pub fn get_database_type(file_name: &String) -> Result<PasswordDatabaseType, Error> {
    let l = file_name.len();
    if l < 6 {
        return Err(Error::new(ErrorKind::InvalidInput, "file name is too short"));
    }
    let suffix = &file_name[l-5..l];
    match suffix {
        ".kdbx" => Ok(PasswordDatabaseType::KeePass),
        ".pdbf" => Ok(PasswordDatabaseType::Pman),
        _ => return Err(Error::new(ErrorKind::InvalidInput, "unsupported database type"))
    }
}

pub fn prepare(data: &Vec<u8>, file_name: String) -> Result<u64, PmanError> {
    let database_type = get_database_type(&file_name)
        .map_err(|e|PmanError::message(e.to_string()))?;
    let f_name = Some(file_name.clone());
    match unsafe{DATABASES.as_ref()}.unwrap().into_iter()
        .find(|(_id, db)|db.file_name == f_name) {
        None => {
            let database = match database_type {
                PasswordDatabaseType::KeePass =>
                    KeePassDatabase::new_from_file(data)
                        .map_err(|e| PmanError::message(e.to_string()))?,
                PasswordDatabaseType::Pman =>
                    PmanDatabase::new_from_file(data)
                        .map_err(|e| PmanError::message(e.to_string()))?,
            };
            let db_id = unsafe{NEXT_DB_ID};
            unsafe{
                DATABASES.as_mut().unwrap()
                    .insert(db_id, DatabaseFile{file_name: f_name, database});
                NEXT_DB_ID += 1
            };
            Ok(db_id)
        },
        Some(_) => Err(PmanError::message("database already added"))
    }
}

pub fn create(database_type: PasswordDatabaseType, password: String, password2: Option<String>,
              key_file_contents: Option<Vec<u8>>) -> Result<u64, PmanError> {
    let database = match database_type {
        PasswordDatabaseType::KeePass =>
            KeePassDatabase::new(password, password2, key_file_contents)
                .map_err(|e| PmanError::message(e.to_string()))?,
        PasswordDatabaseType::Pman =>
            PmanDatabase::new(password, password2, key_file_contents)
                .map_err(|e| PmanError::message(e.to_string()))?,
    };
    let db_id = unsafe{NEXT_DB_ID};
    unsafe{
        DATABASES.as_mut().unwrap()
            .insert(db_id, DatabaseFile{file_name: None, database});
        NEXT_DB_ID += 1
    };
    Ok(db_id)
}

fn get_database(database_id: u64) -> Result<Arc<RwLock<dyn PasswordDatabase>>, PmanError> {
    match unsafe{DATABASES.as_ref()}.unwrap().get(&database_id) {
        None => Err(PmanError::message("database not found")),
        Some(db) => Ok(db.database.clone())
    }
}

pub fn is_read_only(database_id: u64) -> Result<bool, PmanError> {
    let db = get_database(database_id)?;
    let result = db.read().unwrap().is_read_only();
    Ok(result)
}

pub fn pre_open(database_id: u64, password: String, password2: Option<String>, key_file_contents: Option<Vec<u8>>)
                   -> Result<Vec<Arc<DownloadAction>>, PmanError> {
    let db = get_database(database_id)?;
    let result = db.write().unwrap().pre_open(password, password2, key_file_contents)
        .map(|v|v.into_iter().map(|a|Arc::new(a)).collect())
        .map_err(|e|PmanError::message(e.to_string()));
    result
}
