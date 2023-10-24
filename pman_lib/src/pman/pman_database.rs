use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex, MutexGuard};
use crate::error_builders::build_not_found_error;
use crate::pman::database_entity::PmanDatabaseEntity;
use crate::pman::id_value_map::id_value_map::ByteValue;
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
        self.add_to_list(USERS_ID, name, string_validator)
    }

    fn remove_user(&self, user_id: u32) -> Result<(), Error> {
        self.check_user_exists(user_id)?;
        let entities = self.get_all_entities()?;
        if entities.iter().find(|(_id, e)|e.get_user_id() == user_id).is_some() {
            return Err(Error::new(ErrorKind::InvalidInput, "user name is in use"));
        }
        self.remove_from_list(USERS_ID, user_id)
    }

    fn search(&self, search_string: String) -> Result<HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity>>>, Error> {
        todo!()
    }

    fn add_group(&self, name: String) -> Result<u32, Error> {
        self.add_to_list(GROUPS_ID, name, string_validator)
    }

    fn rename_group(&self, group_id: u32, new_name: String) -> Result<(), Error> {
        self.check_group_exists(group_id)?;
        let mut file = self.file.lock().unwrap();
        let indexes: Vec<u32> = file.get_from_names_file(GROUPS_ID)?;
        string_validator(&indexes, &mut file, &new_name)?;
        file.set_in_names_file(group_id, new_name)
    }

    fn delete_group(&self, group_id: u32) -> Result<(), Error> {
        self.check_group_exists(group_id)?;
        let entities = self.get_entities(group_id)?;
        if entities.len() > 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "group is not empty"));
        }
        self.remove_from_list(GROUPS_ID, group_id)
    }

    fn delete_entity(&self, entity_id: u32) -> Result<(), Error> {
        self.check_exists(ENTITIES_ID, entity_id, "entity not found")?;
        let mut file = self.file.lock().unwrap();
        let entity: PmanDatabaseEntity = file.get_from_names_file(entity_id)?;
        let names_ids = entity.collect_names_ids();
        let passwords_ids = entity.collect_passwords_ids();
        for id in names_ids {
            file.remove_from_names_file(id)?;
        }
        for id in passwords_ids {
            file.remove_from_passwords_file(id)?;
        }
        file.remove_from_names_file(entity_id)?;
        drop(file);
        self.remove_from_list(ENTITIES_ID, entity_id)
    }

    fn add_entity(&self, group_id: u32, name: String, user_id: u32, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<u32, Error> {
        self.check_group_exists(group_id)?;
        self.check_user_exists(user_id)?;
        for (_key, value) in self.get_entities(group_id)? {
            if value.get_name()? == name {
                return Err(Error::new(ErrorKind::AlreadyExists, "entity with given name already exists"));
            }
        }
        let mut file = self.file.lock().unwrap();
        let name_id = file.add_to_names_file(name)?;
        let password_id = file.add_to_passwords_file(password)?;
        let url_id = if let Some(u) = url {
            Some(file.add_to_names_file(u)?)
        } else { None };
        let mut property_ids = HashMap::new();
        for (k, v) in properties {
            let key_id = file.add_to_names_file(k)?;
            let value_id = file.add_to_passwords_file(v)?;
            property_ids.insert(key_id, value_id);
        }
        drop(file);
        let entity = PmanDatabaseEntity::new(self.file.clone(), name_id,
                                             password_id, group_id, user_id, url_id, property_ids);
        self.add_to_entity_list(entity)
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

    fn add_to_list<T: ByteValue>(&self, id: u32, value: T,
                                 validator: fn(indexes: &Vec<u32>, file: &mut MutexGuard<PmanDatabaseFile>, value: &T) -> Result<(), Error>) -> Result<u32, Error> {
        let mut file = self.file.lock().unwrap();
        let mut indexes: Vec<u32> = match file.get_from_names_file(id) {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    Vec::new()
                } else {
                    return Err(e);
                }
            }
        };
        validator(&indexes, &mut file, &value)?;
        let idx = file.add_to_names_file(value)?;
        indexes.push(idx);
        file.set_in_names_file(id, indexes)?;
        Ok(idx)
    }

    fn add_to_entity_list(&self, value: PmanDatabaseEntity) -> Result<u32, Error> {
        self.add_to_list(ENTITIES_ID, value, no_validator)
    }

    fn check_exists(&self, list_id: u32, id: u32, error_message: &str) -> Result<(), Error> {
        let items: Vec<u32> = self.file.lock().unwrap().get_from_names_file(list_id)?;
        if items.into_iter().find(|i|*i == id).is_none() {
            return Err(Error::new(ErrorKind::NotFound, error_message));
        }
        Ok(())
    }

    fn check_group_exists(&self, group_id: u32) -> Result<(), Error> {
        self.check_exists(GROUPS_ID, group_id, "group not found")
    }

    fn check_user_exists(&self, user_id: u32) -> Result<(), Error> {
        self.check_exists(USERS_ID, user_id, "user not found")
    }

    fn remove_from_list(&self, list_id: u32, id: u32) -> Result<(), Error> {
        let mut file = self.file.lock().unwrap();
        let mut indexes: Vec<u32> = file.get_from_names_file(list_id)?;
        for i in 0..indexes.len() {
            if indexes[i] == id {
                file.remove_from_names_file(id)?;
                indexes.remove(i);
                return file.set_in_names_file(list_id, indexes)
            }
        }
        Err(build_not_found_error())
    }
}

fn string_validator(indexes: &Vec<u32>, file: &mut MutexGuard<PmanDatabaseFile>, value: &String) -> Result<(), Error> {
    let data: HashMap<u32, String> = file.mget_from_names_file(indexes.clone().into_iter().collect())?;
    if data.into_iter().find(|(_id, name)|*name == *value).is_some() {
        return Err(Error::new(ErrorKind::AlreadyExists, "item with the same name already exists"));
    }
    Ok(())
}

fn no_validator<T: ByteValue>(_indexes: &Vec<u32>, _file: &mut MutexGuard<PmanDatabaseFile>, _value: &T) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Error;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::pman::pman_database::PmanDatabase;

    #[test]
    fn test_database() -> Result<(), Error> {
        let mut hash1 = [0u8; 32];
        OsRng.fill_bytes(&mut hash1);
        let mut hash2 = [0u8; 32];
        OsRng.fill_bytes(&mut hash2);
        let hash1_vec = Vec::from(hash1);
        let hash2_vec = Vec::from(hash2);
        let database = PmanDatabase::new(hash1_vec, hash2_vec)?;
        let internet_group = database.add_group("Internet".to_string())?;
        let banks_group = database.add_group("Banks".to_string())?;
        let others_group = database.add_group("Others".to_string())?;
        let user1 = database.add_user("user1@a.com".to_string())?;
        let user2 = database.add_user("user2@b.com".to_string())?;
        let user3 = database.add_user("user3@c.com".to_string())?;
        let name1 = "Amazon".to_string();
        let password1 = "some password".to_string();
        let url1 = Some("amazon.com".to_string());
        let p1 = "PIN".to_string();
        let pv1 = "12345".to_string();
        let entity = database.add_entity(internet_group, name1.clone(),
                                         user1, password1.clone(),
                                         url1.clone(),
                                         HashMap::from([(p1.clone(), pv1.clone())]))?;
        let entities = database.get_entities(internet_group)?;
        assert_eq!(entities.len(), 1);
        let e = entities.get(&entity);
        assert!(e.is_some());
        let en = e.unwrap();
        assert_eq!(en.get_name()?, name1);
        assert_eq!(en.get_group_id(), internet_group);
        assert_eq!(en.get_user_id(), user1);
        assert_eq!(en.get_password()?, password1);
        let names = en.get_property_names()?;
        assert_eq!(names.len(), 1);
        let p1value = names.get(&p1);
        assert!(p1value.is_some());
        let p1value_string = en.get_property_value(*p1value.unwrap())?;
        assert_eq!(p1value_string, pv1);
        Ok(())
    }
}