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

pub trait PasswordDatabaseEntity {
    fn get_name(&self) -> Result<String, Error>;
    fn get_user_id(&self) -> u32;
    fn get_group_id(&self) -> u32;
    fn get_password(&self) -> Result<String, Error>;
    fn get_url(&self) -> Result<Option<String>, Error>;
    fn get_property_names(&self) -> Result<HashMap<u32, String>, Error>;
    fn get_property_value(&self, index: u32) -> Result<String, Error>;

    fn modify(&mut self, new_group_id: Option<u32>, new_name: Option<String>, new_user_id: Option<u32>,
              new_password: Option<String>, new_url: Option<String>, new_properties: HashMap<String, String>,
              modified_properties: HashMap<u32, Option<String>>)
        -> Result<(), Error>;
}

pub struct DatabaseGroup {
    pub name: String,
    pub id: u32,
    pub entities_count: u32
}

impl DatabaseGroup {
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    pub fn get_entities_count(&self) -> u32 {
        self.entities_count
    }
}

pub trait PasswordDatabase {
    fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16)
        -> Result<(), Error>;
    fn is_read_only(&self) -> bool;
    // pre_open - tries to decrypt local file and returns download file actions.
    fn pre_open(&mut self, main_file_name: &String, password_hash: Vec<u8>,
                password2_hash: Option<Vec<u8>>, key_file_contents: Option<Vec<u8>>)
                -> Result<Vec<String>, Error>;
    // open - opens database using download results.
    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error>;
    fn get_groups(&mut self) -> Result<Vec<DatabaseGroup>, Error>;
    fn get_users(&mut self) -> Result<HashMap<u32, String>, Error>;
    fn get_entities(&mut self, group_id: u32) -> Result<HashMap<u32, Box<dyn PasswordDatabaseEntity>>, Error>;
    fn add_user(&mut self, name: String) -> Result<u32, Error>;
    fn remove_user(&mut self, id: u32) -> Result<(), Error>;
    fn search(&mut self, search_string: String) -> Result<HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity>>>, Error>;
    fn add_group(&mut self, name: String) -> Result<u32, Error>;
    fn rename_group(&mut self, group_id: u32, new_name: String) -> Result<(), Error>;
    fn delete_group(&mut self, id: u32) -> Result<(), Error>;
    fn delete_entity(&mut self, entity_id: u32) -> Result<(), Error>;
    fn add_entity(&mut self, group_id: u32, name: String, user_id: u32, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<u32, Error>;
    fn modify_entity(&mut self, entity_id: u32, new_group_id: Option<u32>, new_name: Option<String>,
                     new_user_id: Option<u32>, new_password: Option<String>, new_url: Option<String>,
                     properties: HashMap<String, String>) -> Result<(), Error>;
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