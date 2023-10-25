use std::any::Any;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use crate::error_builders::build_read_only_db_error;
use crate::structs_interfaces::{DatabaseGroup, FileAction, PasswordDatabase, PasswordDatabaseEntity};

pub struct KeePassDatabase {

}

impl PasswordDatabase for KeePassDatabase {
    fn set_argon2(&self, _hash_id: usize, _iterations: u8, _parallelism: u8, _memory: u16) -> Result<(), Error> {
        todo!()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn pre_open(&self, _main_file_name: &String, _password_hash: Vec<u8>,
                _password2_hash: Option<Vec<u8>>, _key_file_contents: Option<Vec<u8>>)
            -> Result<Vec<String>, Error> {
        todo!()
    }

    fn open(&self, _data: Vec<Vec<u8>>) -> Result<(), Error> {
        todo!()
    }

    fn get_groups(&self) -> Result<Vec<DatabaseGroup>, Error> {
        todo!()
    }

    fn get_users(&self) -> Result<HashMap<u32, String>, Error> {
        todo!()
    }

    fn get_entities(&self, _group_id: u32) -> Result<HashMap<u32, Box<dyn PasswordDatabaseEntity + Send>>, Error> {
        todo!()
    }

    fn add_user(&self, _name: String) -> Result<u32, Error> {
        Err(build_read_only_db_error())
    }

    fn remove_user(&self, _id: u32) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn search(&self, _search_string: String) -> Result<HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity + Send>>>, Error> {
        todo!()
    }

    fn add_group(&self, _name: String) -> Result<u32, Error> {
        Err(build_read_only_db_error())
    }

    fn rename_group(&self, _group_id: u32, _new_name: String) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn remove_group(&self, _group_id: u32) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn remove_entity(&self, _entity_id: u32) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn add_entity(&self, _group_id: u32, _name: String, _user_id: u32, _password: String,
                  _url: Option<String>, _properties: HashMap<String, String>) -> Result<u32, Error> {
        Err(build_read_only_db_error())
    }

    fn rename_entity(&self, _entity_id: u32, _new_name: String) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn modify_entity(&self, _entity_id: u32, _new_group_id: Option<u32>,
                     _new_user_id: Option<u32>, _new_password: Option<String>, _new_url: Option<String>,
                     _new_properties: HashMap<String, String>,
                     _modified_properties: HashMap<u32, Option<String>>) -> Result<(), Error> {
        Err(build_read_only_db_error())
    }

    fn save(&self, _file_name: String) -> Result<Vec<FileAction>, Error> {
        Err(build_read_only_db_error())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl KeePassDatabase {
    pub fn new_from_file(_contents: Vec<u8>) -> Result<Box<dyn PasswordDatabase>, Error> {
        Ok(Box::new(KeePassDatabase{}))
    }

    pub fn new(_password_hash: Vec<u8>, _key_file_contents: Option<Vec<u8>>)
        -> Result<Box<dyn PasswordDatabase>, Error> {
        Err(Error::new(ErrorKind::Unsupported, "not implemented"))
    }

    fn open(&mut self, _password: String, _password2: Option<String>,
            _key_file_contents: Option<Vec<u8>>) -> Result<KeePassDatabase, Error> {
        todo!()
    }
}