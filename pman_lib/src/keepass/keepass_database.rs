use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use crate::error_builders::build_read_only_db_error;
use crate::structs_interfaces::{DatabaseGroup, FileAction, PasswordDatabase, PasswordDatabaseEntity};

pub struct KeePassDatabase {

}

impl PasswordDatabase for KeePassDatabase {
    fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        todo!()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn pre_open(&mut self, main_file_name: &String, password_hash: Vec<u8>,
                password2_hash: Option<Vec<u8>>, key_file_contents: Option<Vec<u8>>)
            -> Result<Vec<String>, Error> {
        todo!()
    }

    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        todo!()
    }

    fn get_groups(&mut self) -> Result<Vec<DatabaseGroup>, Error> {
        todo!()
    }

    fn get_users(&mut self) -> Result<HashMap<u32, String>, Error> {
        todo!()
    }

    fn get_entities(&mut self, group_id: u32) -> Result<HashMap<u32, Box<dyn PasswordDatabaseEntity>>, Error> {
        todo!()
    }

    fn add_user(&mut self, name: String) -> Result<u32, Error> {
        Err(build_read_only_db_error())
    }

    fn remove_user(&mut self, id: u32) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn search(&mut self, search_string: String) -> Result<HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity>>>, Error> {
        todo!()
    }

    fn add_group(&mut self, name: String) -> Result<u32, Error> {
        Err(build_read_only_db_error())
    }

    fn rename_group(&mut self, group_id: u32, new_name: String) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn delete_group(&mut self, group_id: u32) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn delete_entity(&mut self, entity_id: u32) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn add_entity(&mut self, group_id: u32, name: String, user_id: u32, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<u32, Error> {
        Err(build_read_only_db_error())
    }

    fn modify_entity(&mut self, entity_id: u32, new_group_id: Option<u32>, new_name: Option<String>,
                     new_user_id: Option<u32>, new_password: Option<String>, new_url: Option<String>,
                     properties: HashMap<String, String>) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn save(&mut self, file_name: String) -> Result<Vec<FileAction>, Error> {
        Err(build_read_only_db_error())
    }
}

impl KeePassDatabase {
    pub fn new_from_file(_contents: Vec<u8>) -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        Ok(Arc::new(RwLock::new(KeePassDatabase{})))
    }

    pub fn new(password_hash: Vec<u8>, key_file_contents: Option<Vec<u8>>)
        -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        Err(Error::new(ErrorKind::Unsupported, "not implemented"))
    }

    fn open(&mut self, password: String, password2: Option<String>,
            key_file_contents: Option<Vec<u8>>) -> Result<KeePassDatabase, Error> {
        todo!()
    }
}