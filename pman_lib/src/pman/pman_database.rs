use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, RwLock};
use crate::pman::database_entity::PmanDatabaseEntity;
use crate::pman::pman_database_file::PmanDatabaseFile;
use crate::structs_interfaces::{DatabaseGroup, FileAction, PasswordDatabase, PasswordDatabaseEntity};

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
        let groups: HashMap<u32, String> = match self.file.get_indirect_from_names_file(GROUPS_ID) {
            Ok(g) => g,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    return Ok(Vec::new());
                } else {
                    return Err(e);
                }
            }
        };
        let entities = self.get_entities()?;
        let mut counts = HashMap::new();
        for (id, entity) in entities {
            let e = counts.entry(entity.get_group_id()).or_insert(0u32);
            *e += 1;
        }
        Ok(groups.into_iter().map(|(id, g)|DatabaseGroup{
            name: g,
            id,
            entities_count: *counts.get(&id).unwrap_or(&0),
        }).collect())
    }

    fn get_users(&mut self) -> Result<HashMap<u32, String>, Error> {
        self.file.get_indirect_from_names_file(USERS_ID)
    }

    fn get_entities(&mut self, group_id: u32) -> Result<HashMap<u32, Box<dyn PasswordDatabaseEntity>>, Error> {
        let entities = self.get_entities()?;
        let mut result: HashMap<u32, Box<dyn PasswordDatabaseEntity>> = HashMap::new();
        for (k, v) in entities {
            if v.get_group_id() == group_id {
                result.insert(k, Box::new(v));
            }
        }
        Ok(result)
    }

    fn add_user(&mut self, name: String) -> Result<u32, Error> {
        self.add_to_string_list(USERS_ID, name)
    }

    fn remove_user(&mut self, id: u32) -> Result<(), Error> {
        todo!()
    }

    fn search(&mut self, search_string: String) -> Result<HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity>>>, Error> {
        todo!()
    }

    fn add_group(&mut self, name: String) -> Result<u32, Error> {
        self.add_to_string_list(GROUPS_ID, name)
    }

    fn rename_group(&mut self, group_id: u32, new_name: String) -> Result<(), Error> {
        todo!()
    }

    fn delete_group(&mut self, group_id: u32) -> Result<(), Error> {
        todo!()
    }

    fn delete_entity(&mut self, entity_id: u32) -> Result<(), Error> {
        todo!()
    }

    fn add_entity(&mut self, group_id: u32, name: String, user_id: u32, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<u32, Error> {
        todo!()
    }

    fn modify_entity(&mut self, entity_id: u32, new_group_id: Option<u32>, new_name: Option<String>,
                     new_user_id: Option<u32>, new_password: Option<String>, new_url: Option<String>,
                     properties: HashMap<String, String>) -> Result<(), Error> {
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

    pub fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<Arc<RwLock<dyn PasswordDatabase>>, Error> {
        let file = PmanDatabaseFile::new(password_hash, password2_hash)?;
        Ok(Arc::new(RwLock::new(PmanDatabase{file})))
    }

    pub fn pre_open(&mut self, main_file_name: &String, password_hash: Vec<u8>,
                    password2_hash: Vec<u8>) -> Result<Vec<String>, Error> {
        self.file.pre_open(main_file_name, password_hash, password2_hash)
    }

    pub fn open(&mut self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        self.file.open(data)
    }

    fn get_entities(&mut self) -> Result<HashMap<u32, PmanDatabaseEntity>, Error> {
        self.file.get_indirect_from_names_file(ENTITIES_ID)
    }

    fn add_to_string_list(&mut self, id: u32, value: String) -> Result<u32, Error> {
        let mut indexes: Vec<u32> = self.file.get_from_names_file(id)?;
        let data: HashMap<u32, String> = self.file.mget_from_names_file(indexes.clone().into_iter().collect())?;
        if data.into_iter().find(|(id, name)|*name == value).is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "item with the same name already exists"));
        }
        let idx = self.file.add_to_names_file(value)?;
        indexes.push(idx);
        self.file.set_in_names_file(id, indexes)?;
        Ok(idx)
    }
}