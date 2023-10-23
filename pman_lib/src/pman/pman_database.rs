use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex, RwLock};
use crate::pman::database_entity::PmanDatabaseEntity;
use crate::pman::pman_database_file::PmanDatabaseFile;
use crate::structs_interfaces::{DatabaseGroup, FileAction, PasswordDatabase, PasswordDatabaseEntity};

const GROUPS_ID: u32 = 1;
const USERS_ID: u32 = 2;

const ENTITIES_ID: u32 = 3;

pub struct PmanDatabase {
    file: Arc<Mutex<PmanDatabaseFile>>
}

impl PasswordDatabase for PmanDatabase {
    fn set_argon2(&self, hash_id: usize, iterations: u8, parallelism: u8, memory: u16) -> Result<(), Error> {
        self.file.lock().unwrap().set_argon2(hash_id, iterations, parallelism, memory)
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn pre_open(&self, main_file_name: &String, password_hash: Vec<u8>,
                password2_hash: Option<Vec<u8>>, _key_file_contents: Option<Vec<u8>>)
            -> Result<Vec<String>, Error> {
        if password2_hash.is_none() {
            return Err(Error::new(ErrorKind::InvalidInput, "password2 hash is required"))
        }
        self.file.lock().unwrap().pre_open(main_file_name, password_hash, password2_hash.unwrap())
    }

    fn open(&self, data: Vec<Vec<u8>>) -> Result<(), Error> {
        self.file.lock().unwrap().open(data)
    }

    fn get_groups(&self) -> Result<Vec<DatabaseGroup>, Error> {
        let groups: HashMap<u32, String> = match self.file.lock().unwrap().get_indirect_from_names_file(GROUPS_ID) {
            Ok(g) => g,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    return Ok(Vec::new());
                } else {
                    return Err(e);
                }
            }
        };
        let entities = self.get_all_entities()?;
        let mut counts = HashMap::new();
        for (_id, entity) in entities {
            let e = counts.entry(entity.get_group_id()).or_insert(0u32);
            *e += 1;
        }
        Ok(groups.into_iter().map(|(id, g)|DatabaseGroup{
            name: g,
            id,
            entities_count: *counts.get(&id).unwrap_or(&0),
        }).collect())
    }

    fn get_users(&self) -> Result<HashMap<u32, String>, Error> {
        self.file.lock().unwrap().get_indirect_from_names_file(USERS_ID)
    }

    fn get_entities(&self, group_id: u32) -> Result<HashMap<u32, Box<dyn PasswordDatabaseEntity>>, Error> {
        let entities = self.get_all_entities()?;
        let mut result: HashMap<u32, Box<dyn PasswordDatabaseEntity>> = HashMap::new();
        for (k, v) in entities {
            if v.get_group_id() == group_id {
                result.insert(k, Box::new(v));
            }
        }
        Ok(result)
    }

    fn add_user(&self, name: String) -> Result<u32, Error> {
        self.add_to_string_list(USERS_ID, name)
    }

    fn remove_user(&self, id: u32) -> Result<(), Error> {
        todo!()
    }

    fn search(&self, search_string: String) -> Result<HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity>>>, Error> {
        todo!()
    }

    fn add_group(&self, name: String) -> Result<u32, Error> {
        self.add_to_string_list(GROUPS_ID, name)
    }

    fn rename_group(&self, group_id: u32, new_name: String) -> Result<(), Error> {
        todo!()
    }

    fn delete_group(&self, group_id: u32) -> Result<(), Error> {
        todo!()
    }

    fn delete_entity(&self, entity_id: u32) -> Result<(), Error> {
        todo!()
    }

    fn add_entity(&self, group_id: u32, name: String, user_id: u32, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<u32, Error> {
        todo!()
    }

    /*fn modify_entity(&self, entity_id: u32, new_group_id: Option<u32>, new_name: Option<String>,
                     new_user_id: Option<u32>, new_password: Option<String>, new_url: Option<String>,
                     new_properties: HashMap<String, String>,
                     modified_properties: HashMap<u32, Option<String>>) -> Result<(), Error> {
        todo!()
    }*/

    fn save(&self, file_name: String) -> Result<Vec<FileAction>, Error> {
        self.file.lock().unwrap().save(file_name)
    }
}

impl PmanDatabase {
    pub fn new_from_file(contents: Vec<u8>) -> Result<Box<dyn PasswordDatabase>, Error> {
        let file = Arc::new(Mutex::new(PmanDatabaseFile::prepare(contents)?));
        Ok(Box::new(PmanDatabase{file}))
    }

    pub fn new(password_hash: Vec<u8>, password2_hash: Vec<u8>) -> Result<Box<dyn PasswordDatabase>, Error> {
        let file = Arc::new(Mutex::new(PmanDatabaseFile::new(password_hash, password2_hash)?));
        Ok(Box::new(PmanDatabase{file}))
    }

    fn get_all_entities(&self) -> Result<HashMap<u32, PmanDatabaseEntity>, Error> {
        let mut entities: HashMap<u32, PmanDatabaseEntity> = self.file.lock().unwrap().get_indirect_from_names_file(ENTITIES_ID)?;
        for (_key, value) in &mut entities {
            value.set_database_file(self.file.clone());
        }
        Ok(entities)
    }

    fn add_to_string_list(&self, id: u32, value: String) -> Result<u32, Error> {
        let mut indexes: Vec<u32> = self.file.lock().unwrap().get_from_names_file(id)?;
        let data: HashMap<u32, String> = self.file.lock().unwrap().mget_from_names_file(indexes.clone().into_iter().collect())?;
        if data.into_iter().find(|(_id, name)|*name == value).is_some() {
            return Err(Error::new(ErrorKind::AlreadyExists, "item with the same name already exists"));
        }
        let idx = self.file.lock().unwrap().add_to_names_file(value)?;
        indexes.push(idx);
        self.file.lock().unwrap().set_in_names_file(id, indexes)?;
        Ok(idx)
    }
}