use std::any::Any;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex, MutexGuard};
use crate::error_builders::build_not_found_error;
use crate::pman::database_entity::{ENTITY_VERSION_LATEST, PmanDatabaseEntity};
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
            let e = counts.entry(entity.get_group_id(ENTITY_VERSION_LATEST)?).or_insert(0u32);
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

    fn get_entities(&self, group_id: u32) -> Result<HashMap<u32, Box<dyn PasswordDatabaseEntity + Send>>, Error> {
        let entities = self.get_all_entities()?;
        let mut result: HashMap<u32, Box<dyn PasswordDatabaseEntity + Send>> = HashMap::new();
        for (k, v) in entities {
            if v.get_group_id(ENTITY_VERSION_LATEST)? == group_id {
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
        if entities.iter().find(|(_id, e)|e.contains_user_id(user_id)).is_some() {
            return Err(Error::new(ErrorKind::InvalidInput, "user name is in use"));
        }
        self.remove_from_list(USERS_ID, user_id)
    }

    fn search(&self, search_string: String) -> Result<HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity + Send>>>, Error> {
        let entities = self.get_all_entities()?;
        let mut result: HashMap<u32, HashMap<u32, Box<dyn PasswordDatabaseEntity + Send>>> = HashMap::new();
        for (entity_id, entity) in entities {
            if entity.get_name()?.to_lowercase().contains(&search_string.to_lowercase()) {
                let group_id = entity.get_group_id(ENTITY_VERSION_LATEST)?;
                let map = result.entry(group_id).or_insert(HashMap::new());
                map.insert(entity_id, Box::new(entity));
            }
        }
        Ok(result)
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

    fn remove_group(&self, group_id: u32) -> Result<(), Error> {
        self.check_group_exists(group_id)?;
        let entities = self.get_all_entities()?;
        if entities.iter().find(|(_k, v)|v.contains_group_id(group_id)).is_some() {
            return Err(Error::new(ErrorKind::InvalidInput, "group is not empty"));
        }
        self.remove_from_list(GROUPS_ID, group_id)
    }

    fn remove_entity(&self, entity_id: u32) -> Result<(), Error> {
        self.check_entity_exists(entity_id)?;
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
        self.check_entity_name(group_id, name.clone())?;
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

    fn rename_entity(&self, entity_id: u32, new_name: String) -> Result<(), Error> {
        let entity = self.get_entity(entity_id)?;
        self.check_entity_name(entity.get_group_id(ENTITY_VERSION_LATEST)?, new_name.clone())?;
        self.file.lock().unwrap().set_in_names_file(entity.get_name_id(), new_name)
    }

    fn modify_entity(&self, entity_id: u32, new_group_id: Option<u32>,
                     new_user_id: Option<u32>, new_password: Option<String>, new_url: Option<String>,
                     new_properties: HashMap<String, String>,
                     modified_properties: HashMap<u32, Option<String>>) -> Result<(), Error> {
        let mut entity = self.get_entity(entity_id)?;
        let new_gid = if let Some(gid) = new_group_id {
            self.check_group_exists(gid)?;
            gid
        } else { entity.get_group_id(ENTITY_VERSION_LATEST)? };
        let new_uid = if let Some(uid) = new_user_id {
            self.check_user_exists(uid)?;
            uid
        } else { entity.get_user_id(ENTITY_VERSION_LATEST)? };
        let mut file = self.file.lock().unwrap();
        let new_pid = if let Some(password) = new_password {
            file.add_to_passwords_file(password)?
        } else { entity.get_password_id() };
        let new_url_id = if let Some(url) = new_url {
            Some(file.add_to_names_file(url)?)
        } else { None };
        let mut new_props= entity.get_properties();
        for (k, v) in modified_properties {
            if !new_props.contains_key(&k) {
                return Err(Error::new(ErrorKind::NotFound, "invalid property id"));
            }
            if let Some(value) = v {
                let id = file.add_to_passwords_file(value)?;
                new_props.insert(k, id);
            } else {
                new_props.remove(&k);
            }
        }
        for (k, v) in new_properties {
            self.check_property_name(&new_props, k.clone())?;
            let key_id = file.add_to_names_file(k)?;
            let value_id = file.add_to_passwords_file(v)?;
            new_props.insert(key_id, value_id);
        }
        entity.update(new_pid, new_gid, new_uid, new_url_id, new_props);
        file.set_in_names_file(entity_id, entity)
    }

    fn save(&self, file_name: String) -> Result<Vec<FileAction>, Error> {
        self.file.lock().unwrap().save(file_name)
    }

    fn as_any(&self) -> &dyn Any {
        self
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

    fn check_entity_exists(&self, entity_id: u32) -> Result<(), Error> {
        self.check_exists(ENTITIES_ID, entity_id, "entity not found")
    }

    fn remove_from_list(&self, list_id: u32, id: u32) -> Result<(), Error> {
        let mut file = self.file.lock().unwrap();
        let mut indexes: Vec<u32> = file.get_from_names_file(list_id)?;
        for i in 0..indexes.len() {
            if indexes[i] == id {
                file.remove_from_names_file(id)?;
                indexes.remove(i);
                return if indexes.is_empty() {
                    file.remove_from_names_file(list_id)
                } else {
                    file.set_in_names_file(list_id, indexes)
                }
            }
        }
        Err(build_not_found_error())
    }

    fn get_names_file_records_count(&self) -> Result<usize, Error> {
        self.file.lock().unwrap().get_names_file_records_count()
    }

    fn get_passwords_file_records_count(&self) -> Result<usize, Error> {
        self.file.lock().unwrap().get_passwords_file_records_count()
    }

    fn check_entity_name(&self, group_id: u32, name: String) -> Result<(), Error> {
        for (_key, value) in self.get_entities(group_id)? {
            if value.get_name()? == name {
                return Err(Error::new(ErrorKind::AlreadyExists, "entity with given name already exists"));
            }
        }
        Ok(())
    }

    fn get_entity(&self, entity_id: u32) -> Result<PmanDatabaseEntity, Error> {
        self.check_entity_exists(entity_id)?;
        self.file.lock().unwrap().get_from_names_file(entity_id)
    }

    fn check_property_name(&self, properties: &HashMap<u32, u32>, name: String) -> Result<(), Error> {
        let mut file = self.file.lock().unwrap();
        for (k, _v) in properties {
            let n: String = file.get_from_names_file(*k)?;
            if n == name {
                return Err(Error::new(ErrorKind::AlreadyExists, "duplicate property name"));
            }
        }
        Ok(())
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
    use crate::pman::database_entity::ENTITY_VERSION_LATEST;
    use crate::pman::pman_database::PmanDatabase;
    use crate::structs_interfaces::PasswordDatabase;

    struct TestEntity {
        name: String,
        password: String,
        url: Option<String>,
        group_index: usize,
        user_index: usize,
        properties: HashMap<String, String>
    }
    struct TestData {
        hash1_vec: Vec<u8>,
        hash2_vec: Vec<u8>,
        group_names: Vec<String>,
        user_names: Vec<String>,
        entities: Vec<TestEntity>
    }

    struct TestDatabase {
        test_data: TestData,
        database: Box<dyn PasswordDatabase>,
        group_ids: Vec<u32>,
        user_ids: Vec<u32>,
        entity_ids: Vec<u32>
    }

    fn build_test_data() -> TestData {
        let mut hash1 = [0u8; 32];
        OsRng.fill_bytes(&mut hash1);
        let mut hash2 = [0u8; 32];
        OsRng.fill_bytes(&mut hash2);
        let hash1_vec = Vec::from(hash1);
        let hash2_vec = Vec::from(hash2);

        let group_names = vec!["Internet".to_string(), "Banks".to_string(), "Others".to_string()];
        let user_names = vec!["user1@a.com".to_string(), "user2@b.com".to_string(), "user3@c.com".to_string()];
        let entities = vec![TestEntity{
            name: "Amazon".to_string(),
            password: "some password".to_string(),
            url: Some("amazon.com".to_string()),
            group_index: 0,
            user_index: 0,
            properties: HashMap::from([
                ("PIN".to_string(), "12345".to_string())
            ]),
        }];

        TestData{
            hash1_vec,
            hash2_vec,
            group_names,
            user_names,
            entities
        }
    }

    fn build_database(test_data: TestData) -> Result<TestDatabase, Error> {
        let database = PmanDatabase::new(test_data.hash1_vec.clone(),
                                         test_data.hash2_vec.clone())?;
        let mut group_ids = Vec::new();
        for group_name in &test_data.group_names {
            group_ids.push(database.add_group(group_name.clone())?);
        }
        let mut user_ids = Vec::new();
        for user_name in &test_data.user_names {
            user_ids.push(database.add_user(user_name.clone())?);
        }
        let mut entity_ids = Vec::new();
        for e in &test_data.entities {
            let entity_id = database.add_entity(group_ids[e.group_index], e.name.clone(),
                                                user_ids[e.user_index], e.password.clone(),
                                                e.url.clone(), e.properties.clone())?;
            entity_ids.push(entity_id);
        }
        Ok(TestDatabase{
            test_data,
            database,
            group_ids,
            user_ids,
            entity_ids
        })
    }

    #[test]
    fn test_database() -> Result<(), Error> {
        let test_data = build_test_data();
        let test_database = build_database(test_data)?;
        check_database(&test_database)?;
        test_search(&test_database)?;
        cleanup_database(test_database)
    }

    #[test]
    fn test_database_with_save() -> Result<(), Error> {
        let test_data = build_test_data();
        let mut test_database = build_database(test_data)?;
        let file_name = "some_file.pdbf".to_string();
        let data = test_database.database.save(file_name.clone())?;
        assert_eq!(data.len(), 3);
        assert_eq!(data[0].file_name, file_name.clone());
        assert_eq!(data[1].file_name, file_name.clone() + ".names");
        assert_eq!(data[2].file_name, file_name.clone() + ".passwords");
        let database = PmanDatabase::new_from_file(data[0].data.clone())?;
        let files = database.pre_open(&file_name, test_database.test_data.hash1_vec.clone(),
                          Some(test_database.test_data.hash2_vec.clone()), None)?;
        assert_eq!(files.len(), 2);
        assert_eq!(files[0], file_name.clone() + ".names");
        assert_eq!(files[1], file_name.clone() + ".passwords");
        let open_data = data.into_iter().skip(1).map(|d|d.data).collect();
        database.open(open_data)?;
        test_database.database = database;
        check_database(&test_database)?;
        test_search(&test_database)?;
        cleanup_database(test_database)
    }

    fn check_database(database: &TestDatabase) -> Result<(), Error> {
        let mut entity_map = HashMap::new();
        for i in 0..database.test_data.entities.len() {
            let entity = &database.test_data.entities[i];
            let v = entity_map.entry(database.group_ids[entity.group_index]).or_insert(Vec::new());
            v.push((database.entity_ids[i], i));
        }
        for (group_id, group_entities) in entity_map {
            let entities = database.database.get_entities(group_id)?;
            assert_eq!(entities.len(), group_entities.len());
            for (entity_id, entity_index) in group_entities {
                let e = entities.get(&entity_id);
                assert!(e.is_some());
                let en = e.unwrap();
                let ten = &database.test_data.entities[entity_index];
                assert_eq!(en.get_name()?, ten.name);
                assert_eq!(en.get_group_id(ENTITY_VERSION_LATEST)?, database.group_ids[ten.group_index]);
                assert_eq!(en.get_user_id(ENTITY_VERSION_LATEST)?, database.user_ids[ten.user_index]);
                assert_eq!(en.get_password(ENTITY_VERSION_LATEST)?, ten.password);
                let names = en.get_property_names(ENTITY_VERSION_LATEST)?;
                assert_eq!(names.len(), ten.properties.len());
                for (name, id) in names {
                    let value = ten.properties.get(&name);
                    assert!(value.is_some());
                    let pvalue = en.get_property_value(ENTITY_VERSION_LATEST, id)?;
                    assert_eq!(value.unwrap().clone(), pvalue);
                }
            }
        }
        Ok(())
    }

    fn test_search(database: &TestDatabase) -> Result<(), Error> {
        let search_result = database.database.search("ama".to_string())?;
        assert_eq!(search_result.len(), 1);
        let group_result_option = search_result.get(&database.group_ids[0]);
        assert!(group_result_option.is_some());
        let group_result = group_result_option.unwrap();
        assert_eq!(group_result.len(), 1);
        let entity_option = group_result.get(&database.entity_ids[0]);
        assert!(entity_option.is_some());
        Ok(())
    }

    fn cleanup_database(database: TestDatabase) -> Result<(), Error> {
        for entity_id in database.entity_ids {
            database.database.remove_entity(entity_id)?;
        }
        for group_id in database.group_ids {
            database.database.remove_group(group_id)?;
        }
        for user_id in database.user_ids {
            database.database.remove_user(user_id)?;
        }
        let db: &PmanDatabase = database.database.as_any().downcast_ref().unwrap();
        assert_eq!(db.get_passwords_file_records_count()?, 0);
        assert_eq!(db.get_names_file_records_count()?, 0);
        Ok(())
    }
}