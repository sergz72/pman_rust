use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use crate::keepass::keepass_database::KeePassDatabase;
use crate::pman::pman_database::PmanDatabase;
use crate::pman::pman_database_file::{build_argon2_key, build_argon2_properties};
use crate::structs_interfaces::{DatabaseGroup, FileAction, PasswordDatabase, PasswordDatabaseEntity, PasswordDatabaseType};
use crate::structs_interfaces::CryptoEngine;
use crate::structs_interfaces::HashAlgorithm;

mod structs_interfaces;
mod keepass;
mod pman;
mod crypto;
mod error_builders;

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
    database: Box<dyn PasswordDatabase>
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

pub fn create(database_type: PasswordDatabaseType, password_hash: Vec<u8>, password2_hash: Option<Vec<u8>>,
              key_file_contents: Option<Vec<u8>>) -> Result<u64, PmanError> {
    let database = match database_type {
        PasswordDatabaseType::KeePass =>
            KeePassDatabase::new(password_hash, key_file_contents)
                .map_err(|e| PmanError::message(e.to_string()))?,
        PasswordDatabaseType::Pman => {
            if let Some(h) = password2_hash {
                PmanDatabase::new(password_hash, h)
                    .map_err(|e| PmanError::message(e.to_string()))?
            } else {
                return Err(PmanError::message("second password hash is required"));
            }
        },
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
    let result = db.database.is_read_only();
    Ok(result)
}

pub fn pre_open(database_id: u64, password_hash: Vec<u8>, password2_hash: Option<Vec<u8>>, key_file_contents: Option<Vec<u8>>)
                   -> Result<Vec<String>, PmanError> {
    let db = get_database(database_id)?;
    if db.file_name.is_none() {
        return Err(PmanError::message("file name is required"));
    }
    db.database.pre_open(db.file_name.as_ref().unwrap(),
                        password_hash, password2_hash, key_file_contents)
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn open(database_id: u64, data: Vec<Vec<u8>>) -> Result<(), PmanError> {
    let db = get_database(database_id)?;
    db.database.open(data)
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
    db.database.save(db.file_name.as_ref().unwrap().clone())
        .map(|a|a.into_iter().map(|fa|Arc::new(fa)).collect())
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn set_argon2(database_id: u64, hash_id: u64, iterations: u64, parallelism: u64, memory: u64) -> Result<(), PmanError> {
    if iterations > 255 || parallelism > 255 || memory > 65535 {
        return Err(PmanError::message("incorrect argon2 parameters"));
    }
    let db = get_database(database_id)?;
    db.database.set_argon2(hash_id as usize, iterations as u8, parallelism as u8, memory as u16)
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn build_argon2_hash(password: Vec<u8>, iterations: isize, parallelism: isize, memory: isize, salt: [u8; 16]) -> Result<[u8; 32], Error> {
    let properties = build_argon2_properties(iterations as u8, parallelism as u8, memory as u16, salt);
    build_argon2_key(properties, &password)
}

pub fn get_groups(database_id: u64) -> Result<Vec<Arc<DatabaseGroup>>, PmanError> {
    let db = get_database(database_id)?;
    db.database.get_groups()
        .map(|v|v.into_iter().map(|e|Arc::new(e)).collect())
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn add_group(database_id: u64, name: String) -> Result<u32, PmanError> {
    let db = get_database(database_id)?;
    db.database.add_group(name).map_err(|e|PmanError::message(e.to_string()))
}


pub fn rename_group(database_id: u64, id: u32, new_name: String) -> Result<(), PmanError> {
    let db = get_database(database_id)?;
    db.database.rename_group(id, new_name).map_err(|e|PmanError::message(e.to_string()))
}

pub fn remove_group(database_id: u64, id: u32) -> Result<(), PmanError> {
    let db = get_database(database_id)?;
    db.database.remove_group(id).map_err(|e|PmanError::message(e.to_string()))
}

pub fn get_users(database_id: u64) -> Result<HashMap<u32, String>, PmanError> {
    let db = get_database(database_id)?;
    db.database.get_users().map_err(|e|PmanError::message(e.to_string()))
}

pub fn add_user(database_id: u64, name: String) -> Result<u32, PmanError> {
    let db = get_database(database_id)?;
    db.database.add_user(name).map_err(|e|PmanError::message(e.to_string()))
}

pub fn remove_user(database_id: u64, id: u32) -> Result<(), PmanError> {
    let db = get_database(database_id)?;
    db.database.remove_user(id).map_err(|e|PmanError::message(e.to_string()))
}

pub fn get_entities(database_id: u64, group_id: u32) -> Result<HashMap<u32, Arc<DatabaseEntity>>, PmanError> {
    let db = get_database(database_id)?;
    db.database.get_entities(group_id)
        .map(|v|v.into_iter()
            .map(|(k, v)|(k, Arc::new(DatabaseEntity::new(v)))).collect())
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn add_entity(database_id: u64, name: String, group_id: u32, user_id: u32, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<u32, PmanError> {
    let db = get_database(database_id)?;
    db.database.add_entity(group_id, name, user_id, password, url, properties)
        .map_err(|e|PmanError::message(e.to_string()))
}

pub fn remove_entity(database_id: u64, id: u32) -> Result<(), PmanError> {
    let db = get_database(database_id)?;
    db.database.remove_entity(id).map_err(|e|PmanError::message(e.to_string()))
}

pub fn search(database_id: u64, search_string: String)
    -> Result<HashMap<u32, HashMap<u32, Arc<DatabaseEntity>>>, PmanError> {
    let db = get_database(database_id)?;
    db.database.search(search_string)
        .map(|v|v.into_iter()
            .map(|(k, v)|(k, build_entity_map(v))).collect())
        .map_err(|e|PmanError::message(e.to_string()))
}

fn build_entity_map(map: HashMap<u32, Box<dyn PasswordDatabaseEntity + Send>>) -> HashMap<u32, Arc<DatabaseEntity>> {
    map.into_iter()
        .map(|(k, v)|(k, Arc::new(DatabaseEntity::new(v)))).collect()
}

pub struct DatabaseEntity {
    entity: Mutex<Box<dyn PasswordDatabaseEntity + Send>>
}

impl DatabaseEntity {
    pub fn new(entity: Box<dyn PasswordDatabaseEntity + Send>) -> DatabaseEntity {
        DatabaseEntity{entity: Mutex::new(entity)}
    }

    fn get_name(&self) -> Result<String, PmanError> {
        self.entity.lock().unwrap().get_name().map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_user_id(&self, version: u32) -> Result<u32, PmanError> {
        self.entity.lock().unwrap().get_user_id(version).map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_group_id(&self, version: u32) -> Result<u32, PmanError> {
        self.entity.lock().unwrap().get_group_id(version).map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_password(&self, version: u32) -> Result<String, PmanError> {
        self.entity.lock().unwrap().get_password(version).map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_url(&self, version: u32) -> Result<Option<String>, PmanError> {
        self.entity.lock().unwrap().get_url(version).map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_property_names(&self, version: u32) -> Result<HashMap<String, u32>, PmanError> {
        self.entity.lock().unwrap().get_property_names(version).map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_property_value(&self, version: u32, index: u32) -> Result<String, PmanError> {
        self.entity.lock().unwrap().get_property_value(version, index).map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_created_at(&self, version: u32) -> Result<u64, PmanError> {
        self.entity.lock().unwrap().get_created_at(version).map_err(|e|PmanError::message(e.to_string()))
    }

    fn get_max_version(&self) -> u32 {
        self.entity.lock().unwrap().get_max_version()
    }

    fn modify(&self, new_name: Option<String>, new_group_id: Option<u32>, new_user_id: Option<u32>,
              new_password: Option<String>, new_url: Option<String>, new_properties: HashMap<String, String>,
              modified_properties: HashMap<u32, Option<String>>)
              -> Result<(), PmanError> {
        self.entity.lock().unwrap().modify(new_group_id, new_name, new_user_id, new_password, new_url,
                           new_properties, modified_properties)
            .map_err(|e|PmanError::message(e.to_string()))
    }
}
