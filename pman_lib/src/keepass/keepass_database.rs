use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use crate::structs_interfaces::{DatabaseSearchResult, DownloadAction, PasswordDatabase, SaveAction};

pub struct KeePassDatabase {

}

pub fn build_read_only_db_error() -> Error {
    Error::new(ErrorKind::Unsupported, "database is read only")
}

impl PasswordDatabase for KeePassDatabase {
    fn create(&mut self, password: String, password2: Option<String>,
              key_file_contents: Option<Vec<u8>>) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn prepare(&mut self, contents: &Vec<u8>) -> Result<(), Error> {
        todo!()
    }

    fn pre_open(&mut self, password: String, password2: Option<String>,
                key_file_contents: Option<Vec<u8>>) -> Result<Vec<DownloadAction>, Error> {
        todo!()
    }

    fn open(&mut self, download_result: Vec<&Vec<u8>>) -> Result<(), Error> {
        todo!()
    }

    fn get_users(&self) -> Result<HashMap<usize, String>, Error> {
        todo!()
    }

    fn add_user(&mut self, name: String) -> Result<usize, Error> {
        Err(build_read_only_db_error())
    }

    fn remove_user(&mut self, id: usize) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn search(&self, search_string: String) -> Result<Vec<DatabaseSearchResult>, Error> {
        todo!()
    }

    fn add_group(&mut self, name: String) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn delete_group(&mut self, name: String) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn delete_entity(&mut self, group: String, name: String) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn add_entity(&mut self, group: String, name: String, user_id: usize, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn save(&mut self) -> Result<SaveAction, Error> {
        Err(build_read_only_db_error())
    }
}

impl KeePassDatabase {
    pub fn new_from_file(contents: &Vec<u8>) -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        let mut database = KeePassDatabase {};
        database.prepare(contents)?;
        Ok(Arc::new(RwLock::new(database)))
    }

    pub fn new(password: String, password2: Option<String>,
               key_file_contents: Option<Vec<u8>>) -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        Err(Error::new(ErrorKind::Unsupported, "not implemented"))
    }
}