use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use crate::keepass::keepass_database::KeePassDatabase;
use crate::pman::pman_database::PmanDatabase;
use crate::pman::pman_database_file::{build_argon2_key, build_argon2_properties};
use crate::structs_interfaces::{FileAction, PasswordDatabase, PasswordDatabaseType};
use crate::structs_interfaces::CryptoEngine;
use crate::structs_interfaces::HashAlgorithm;

mod structs_interfaces;
mod keepass;
mod pman;
mod crypto;

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

pub fn prepare(data: Vec<u8>, file_name: String) -> Result<u64, PmanError> {
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

fn get_database<'a>(database_id: u64) -> Result<&'a DatabaseFile, PmanError> {
    match unsafe{DATABASES.as_ref()}.unwrap().get(&database_id) {
        None => Err(build_database_not_found_error()),
        Some(db) => Ok(&db)
    }
}

fn build_database_not_found_error() -> PmanError {
    PmanError::message("database not found")
}

pub fn is_read_only(database_id: u64) -> Result<bool, PmanError> {
    let db = get_database(database_id)?;
    let result = db.database.read().unwrap().is_read_only();
    Ok(result)
}

pub fn pre_open(database_id: u64, password_hash: Vec<u8>, password2_hash: Option<Vec<u8>>, key_file_contents: Option<Vec<u8>>)
                   -> Result<Vec<String>, PmanError> {
    let db = get_database(database_id)?;
    if db.file_name.is_none() {
        return Err(PmanError::message("file name is required"));
    }
    let mut write_lock = db.database.write().unwrap();
    write_lock.pre_open(db.file_name.as_ref().unwrap(),
                        password_hash, password2_hash, key_file_contents)
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn open(database_id: u64, data: Vec<Vec<u8>>) -> Result<(), PmanError> {
    let db = get_database(database_id)?;
    let mut write_lock = db.database.write().unwrap();
    write_lock.open(data)
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn close(database_id: u64) -> Result<(), PmanError> {
    if unsafe{DATABASES.as_mut()}.unwrap().remove(&database_id).is_none() {
        return Err(build_database_not_found_error());
    }
    Ok(())
}

pub fn save(database_id: u64) -> Result<Vec<Arc<FileAction>>, PmanError> {
    let db = get_database(database_id)?;
    let mut write_lock = db.database.write().unwrap();
    write_lock.save(db.file_name.as_ref().unwrap().clone())
        .map(|a|a.into_iter().map(|fa|Arc::new(fa)).collect())
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn set_argon2(database_id: u64, hash_id: u64, iterations: u64, parallelism: u64, memory: u64) -> Result<(), PmanError> {
    if iterations > 255 || parallelism > 255 || memory > 65535 {
        return Err(PmanError::message("incorrect argon2 parameters"));
    }
    let db = get_database(database_id)?;
    let mut write_lock = db.database.write().unwrap();
    write_lock.set_argon2(hash_id as usize, iterations as u8, parallelism as u8, memory as u16)
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn build_argon2_hash(password: Vec<u8>, iterations: isize, parallelism: isize, memory: isize, salt: [u8; 16]) -> Result<[u8; 32], Error> {
    let properties = build_argon2_properties(iterations as u8, parallelism as u8, memory as u16, salt);
    build_argon2_key(properties, &password)
}