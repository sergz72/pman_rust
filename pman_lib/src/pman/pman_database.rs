use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use crate::pman::pman_database_file::PmanDatabaseFile;
use crate::structs_interfaces::{DatabaseEntity, DatabaseGroup, DatabaseSearchResult, FileAction, PasswordDatabase};

const GROUPS_ID: u32 = 1;
const USERS_ID: u32 = 2;

const ENTITIES_ID: u32 = 3;

pub struct PmanDatabase {
    file: PmanDatabaseFile
}

impl PasswordDatabase for PmanDatabase {
    fn set_argon2(&mut self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        self.file.set_argon2(hash_id, iterations, parallelism, memory)
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn pre_open(&mut self, main_file_name: &String, password_hash: Vec<u8>,
                password2_hash: Option<Vec<u8>>, key_file_contents: Option<Vec<u8>>)
            -> Result<Vec<String>, Error> {
        if password2_hash.is_none() {
            return Err(Error::new(ErrorKind::InvalidInput, "password2 hash is required"))
        }
        self.file.pre_open(main_file_name, password_hash, password2_hash.unwrap())
    }

    fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        self.file.open(data)
    }

    fn get_groups(&mut self) -> Result<Vec<DatabaseGroup>, Error> {
        let groups: Vec<u8> = match self.file.get_from_names_file(GROUPS_ID) {
            Ok(g) => g,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    Vec::new()
                } else {
                    return Err(e)
                }
            }
        };
        Ok(Vec::new())
    }

    fn get_users(&mut self) -> Result<HashMap<usize, String>, Error> {
        todo!()
    }

    fn get_entities(&mut self, group_id: usize) -> Result<Vec<Box<dyn DatabaseEntity>>, Error> {
        todo!()
    }

    fn add_user(&mut self, name: String) -> Result<usize, Error> {
        todo!()
    }

    fn remove_user(&mut self, id: usize) -> Result<(), Error> {
        todo!()
    }

    fn search(&mut self, search_string: String) -> Result<Vec<DatabaseSearchResult>, Error> {
        todo!()
    }

    fn add_group(&mut self, name: String) -> Result<(), Error> {
        todo!()
    }

    fn rename_group(&mut self, group_id: usize, new_name: String) -> Result<(), Error> {
        todo!()
    }

    fn delete_group(&mut self, group_id: usize) -> Result<(), Error> {
        todo!()
    }

    fn delete_entity(&mut self, entity_id: usize) -> Result<(), Error> {
        todo!()
    }

    fn add_entity(&mut self, group_id: usize, name: String, user_id: usize, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<(), Error> {
        todo!()
    }

    fn modify_entity(&mut self, entity_id: usize, group_id: usize, name: String, user_id: usize,
                     password: String, url: Option<String>, properties: HashMap<String, String>)
                     -> Result<(), Error> {
        todo!()
    }

    fn save(&mut self, file_name: String) -> Result<Vec<FileAction>, Error> {
        self.file.save(file_name)
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