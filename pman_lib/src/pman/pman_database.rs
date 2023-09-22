use std::collections::HashMap;
use std::io::Error;
use std::sync::{Arc, RwLock};
use crate::structs_interfaces::{DatabaseSearchResult, DownloadAction, PasswordDatabase, SaveAction};

pub struct PmanDatabase {

}

impl PasswordDatabase for PmanDatabase {
    fn is_read_only(&self) -> bool {
        false
    }

    fn prepare(&mut self, contents: &Vec<u8>) -> Result<(), Error> {
        todo!()
    }

    fn pre_open(&mut self, password: String, password2: Option<String>, key_file_contents: &Vec<u8>) -> Result<Vec<DownloadAction>, Error> {
        todo!()
    }

    fn open(&mut self, download_result: Vec<&Vec<u8>>) -> Result<(), Error> {
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

    fn save(&mut self) -> Result<SaveAction, Error> {
        todo!()
    }
}

impl PmanDatabase {
    pub fn new(contents: &Vec<u8>) -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        let mut database = PmanDatabase {};
        database.prepare(contents)?;
        Ok(Arc::new(RwLock::new(database)))
    }
}