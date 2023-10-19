use std::collections::HashMap;
use std::io::Error;
use crate::structs_interfaces::PasswordDatabaseType::Pman;

pub struct FileAction {
    pub file_name: String,
    pub data: Vec<u8>
}

impl FileAction {
    pub fn get_file_name(&self) -> String {
        return self.file_name.clone()
    }
    pub fn get_data(&self) -> Vec<u8> {
        return self.data.clone()
    }

    pub fn new(file_name: String, data: Vec<u8>) -> FileAction {
        FileAction{ file_name, data }
    }
}

pub trait DatabaseEntity {
    fn get_name(&self) -> String;
    fn get_user_id(&self) -> usize;
    fn get_password(&self) -> String;
    fn get_url(&self) -> Option<String>;
    fn get_property_names(&self) -> Vec<String>;
    fn get_property_value(&self, index: usize) -> String;

    fn set_name(&mut self, value: String) -> Result<(), Error>;
    fn set_user_id(&mut self, id: usize) -> Result<(), Error>;
    fn set_password(&mut self, value: String) -> Result<(), Error>;
    fn set_url(&mut self, value: Option<String>) -> Result<(), Error>;
    fn set_property(&mut self, id: usize, value: String) -> Result<(), Error>;
    fn add_property(&mut self, name: String, value: String) -> Result<(), Error>;
    fn delete_property(&mut self, name: String) -> Result<(), Error>;
}

pub struct DatabaseSearchResult {
    pub group_name: String,
    pub entities: Vec<Box<dyn DatabaseEntity>>
}

pub trait PasswordDatabase {
    fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error>;
    fn is_read_only(&self) -> bool;
    // pre_open - tries to decrypt local file and returns download file actions.
    fn pre_open(&mut self, main_file_name: &String, password_hash: Vec<u8>,
                password2_hash: Option<Vec<u8>>, key_file_contents: Option<Vec<u8>>)
                -> Result<Vec<String>, Error>;
    // open - opens database using download results.
    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error>;
    fn get_users(&self) -> Result<HashMap<usize, String>, Error>;
    fn add_user(&mut self, name: String) -> Result<usize, Error>;
    fn remove_user(&mut self, id: usize) -> Result<(), Error>;
    fn search(&self, search_string: String) -> Result<Vec<DatabaseSearchResult>, Error>;
    fn add_group(&mut self, name: String) -> Result<(), Error>;
    fn delete_group(&mut self, name: String) -> Result<(), Error>;
    fn delete_entity(&mut self, group: String, name: String) -> Result<(), Error>;
    fn add_entity(&mut self, group: String, name: String, user_id: usize, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<(), Error>;
    fn save(&mut self, file_name: String) -> Result<Vec<FileAction>, Error>;
}

pub enum HashAlgorithm {
    Argon2
}

pub enum CryptoEngine {
    AES,
    Chacha20
}

#[derive(PartialEq)]
pub enum PasswordDatabaseType {
    KeePass,
    Pman
}

impl PasswordDatabaseType {
    pub fn requires_second_password(&self) -> bool {
        return *self == Pman
    }
}