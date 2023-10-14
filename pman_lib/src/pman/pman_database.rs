use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use crate::pman::pman_database_file::PmanDatabaseFile;
use crate::structs_interfaces::{DatabaseSearchResult, FileAction, PasswordDatabase};

pub struct PmanDatabase {
    file: PmanDatabaseFile
}

impl PasswordDatabase for PmanDatabase {
    fn is_read_only(&self) -> bool {
        false
    }

    fn pre_open(&mut self, password: String, password2: Option<String>, key_file_contents: Option<Vec<u8>>)
            -> Result<Vec<FileAction>, Error> {
        todo!()
    }

    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        todo!()
    }

    fn get_users(&self) -> Result<HashMap<usize, String>, Error> {
        todo!()
    }

    fn add_user(&mut self, name: String) -> Result<usize, Error> {
        todo!()
    }

    fn remove_user(&mut self, id: usize) -> Result<(), Error> {
        todo!()
    }

    fn search(&self, search_string: String) -> Result<Vec<DatabaseSearchResult>, Error> {
        todo!()
    }

    fn add_group(&mut self, name: String) -> Result<(), Error> {
        todo!()
    }

    fn delete_group(&mut self, name: String) -> Result<(), Error> {
        todo!()
    }

    fn delete_entity(&mut self, group: String, name: String) -> Result<(), Error> {
        todo!()
    }

    fn add_entity(&mut self, group: String, name: String, user_id: usize, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<(), Error> {
        todo!()
    }

    fn save(&mut self) -> Result<Vec<u8>, Error> {
        todo!()
    }
}

impl PmanDatabase {
    pub fn new_from_file(contents: Vec<u8>) -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        let file = PmanDatabaseFile::prepare(contents)?;
        Ok(Arc::new(RwLock::new(PmanDatabase{file})))
    }

    pub fn new(password: String, password2: Option<String>,
               key_file_contents: Option<Vec<u8>>) -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        Err(Error::new(ErrorKind::Unsupported, "not implemented"))
    }

    fn open(&mut self, password: String, password2: Option<String>,
                key_file_contents: Option<Vec<u8>>) -> Result<PmanDatabase, Error> {
        todo!()
    }
}