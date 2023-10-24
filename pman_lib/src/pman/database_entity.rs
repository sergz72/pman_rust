use std::collections::{HashMap, HashSet};
use std::io::Error;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use crate::error_builders::{build_corrupted_data_error, build_not_found_error};
use crate::pman::id_value_map::id_value_map::ByteValue;
use crate::pman::pman_database_file::PmanDatabaseFile;
use crate::structs_interfaces::PasswordDatabaseEntity;

#[derive(PartialEq, Eq, Debug)]
pub struct PmanDatabaseEntityFields {
    name_id: u32,
    password_id: u32,
    group_id: u32,
    user_id: u32,
    url_id: Option<u32>,
    created_at: u64,
    // map property name id (in names file) -> property value id (in passwords file)
    properties: HashMap<u32, u32>,
}

impl PmanDatabaseEntityFields {
    fn to_bytes(&self, output: &mut Vec<u8>)  {
        output.extend_from_slice(&self.name_id.to_le_bytes());
        output.extend_from_slice(&self.password_id.to_le_bytes());
        output.extend_from_slice(&self.group_id.to_le_bytes());
        output.extend_from_slice(&self.user_id.to_le_bytes());
        output.extend_from_slice(&self.url_id.unwrap_or(0).to_le_bytes());
        output.extend_from_slice(&self.created_at.to_le_bytes());
        output.push(self.properties.len() as u8);
        for (k, v) in &self.properties {
            output.extend_from_slice(&k.to_le_bytes());
            output.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn from_bytes(source: &Vec<u8>, mut offset: usize) -> Result<(PmanDatabaseEntityFields, usize), Error> {
        if source.len() < offset + 29 {
            return Err(build_corrupted_data_error());
        }
        let mut buffer32 = [0u8; 4];
        buffer32.copy_from_slice(&source[offset..offset+4]);
        offset += 4;
        let name_id = u32::from_le_bytes(buffer32);
        buffer32.copy_from_slice(&source[offset..offset+4]);
        offset += 4;
        let password_id = u32::from_le_bytes(buffer32);
        buffer32.copy_from_slice(&source[offset..offset+4]);
        offset += 4;
        let group_id = u32::from_le_bytes(buffer32);
        buffer32.copy_from_slice(&source[offset..offset+4]);
        offset += 4;
        let user_id = u32::from_le_bytes(buffer32);
        buffer32.copy_from_slice(&source[offset..offset+4]);
        offset += 4;
        let url_id = u32::from_le_bytes(buffer32);
        let mut buffer64 = [0u8; 8];
        buffer64.copy_from_slice(&source[offset..offset+8]);
        offset += 8;
        let created_at = u64::from_le_bytes(buffer64);
        let mut length = source[offset] as usize;
        offset += 1;
        if source.len() < offset + length * 8 {
            return Err(build_corrupted_data_error());
        }
        let mut properties = HashMap::new();
        while length > 0 {
            buffer32.copy_from_slice(&source[offset..offset+4]);
            offset += 4;
            let key = u32::from_le_bytes(buffer32);
            buffer32.copy_from_slice(&source[offset..offset+4]);
            offset += 4;
            let value = u32::from_le_bytes(buffer32);
            if properties.insert(key, value).is_some() {
                return Err(build_corrupted_data_error());
            }
            length -= 1;
        }
        let fields = PmanDatabaseEntityFields{
            name_id,
            password_id,
            group_id,
            user_id,
            url_id: if url_id == 0 { None } else { Some(url_id) },
            created_at,
            properties
        };
        Ok((fields, offset))
    }

    fn collect_names_ids(&self, result: &mut HashSet<u32>) {
        result.insert(self.name_id);
        if let Some(url_id) = self.url_id {
            result.insert(url_id);
        }
        for (k, _v) in &self.properties {
            result.insert(*k);
        }
    }

    fn collect_passwords_ids(&self, result: &mut HashSet<u32>) {
        result.insert(self.password_id);
        for (_k, v) in &self.properties {
            result.insert(*v);
        }
    }
}

pub struct PmanDatabaseEntity {
    database_file: Option<Arc<Mutex<PmanDatabaseFile>>>,
    history: Vec<PmanDatabaseEntityFields>
}

impl ByteValue for PmanDatabaseEntity {
    fn from_bytes(source: Vec<u8>) -> Result<Box<PmanDatabaseEntity>, Error> {
        if source.len() < 29 {
            return Err(build_corrupted_data_error());
        }
        let mut length = source[0];
        let mut history = Vec::new();
        let mut offset = 1;
        while length > 0 {
            let (field, new_offset) = PmanDatabaseEntityFields::from_bytes(&source, offset)?;
            history.push(field);
            offset = new_offset;
            length -= 1;
        }
        if offset != source.len() {
            Err(build_corrupted_data_error())
        } else {
            Ok(Box::new(PmanDatabaseEntity { database_file: None, history }))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.history.len() as u8);
        for item in &self.history {
            item.to_bytes(&mut result);
        }
        result
    }
}

impl PasswordDatabaseEntity for PmanDatabaseEntity {
    fn get_name(&self) -> Result<String, Error> {
        let name_id = self.history.get(0).unwrap().name_id;
        self.database_file.as_ref().unwrap().lock().unwrap().get_from_names_file(name_id)
    }

    fn get_user_id(&self) -> u32 {
        self.history.get(0).unwrap().user_id
    }

    fn get_group_id(&self) -> u32 {
        self.history.get(0).unwrap().group_id
    }

    fn get_password(&self) -> Result<String, Error> {
        let id = self.history.get(0).unwrap().password_id;
        self.database_file.as_ref().unwrap().lock().unwrap().get_from_passwords_file(id)
    }

    fn get_url(&self) -> Result<Option<String>, Error> {
        todo!()
    }

    fn get_property_names(&self) -> Result<HashMap<String, u32>, Error> {
        let mut result = HashMap::new();
        for (k, _v) in &self.history.get(0).unwrap().properties {
            let kk = *k;
            let name = self.database_file.as_ref().unwrap().lock().unwrap().get_from_names_file(kk)?;
            result.insert(name, kk);
        }
        Ok(result)
    }

    fn get_property_value(&self, index: u32) -> Result<String, Error> {
        if let Some(v) = self.history.get(0).unwrap().properties.get(&index) {
            return self.database_file.as_ref().unwrap().lock().unwrap().get_from_passwords_file(*v);
        }
        Err(build_not_found_error())
    }

    fn modify(&mut self, new_group_id: Option<u32>, new_name: Option<String>, new_user_id: Option<u32>,
              new_password: Option<String>, new_url: Option<String>,
              new_properties: HashMap<String, String>,
              modified_properties: HashMap<u32, Option<String>>) -> Result<(), Error> {
        todo!()
    }
}

impl PmanDatabaseEntity {
    pub fn new(database_file: Arc<Mutex<PmanDatabaseFile>>, name_id: u32, password_id: u32, group_id: u32,
               user_id: u32, url_id: Option<u32>, properties: HashMap<u32, u32>) -> PmanDatabaseEntity {
        PmanDatabaseEntity{database_file: Some(database_file), history: vec![PmanDatabaseEntityFields{
            name_id,
            password_id,
            group_id,
            user_id,
            url_id,
            created_at: get_current_timestamp(),
            properties,
        }]}
    }

    pub fn update(&mut self, name_id: u32, password_id: u32, group_id: u32, user_id: u32,
                  url_id: Option<u32>, properties: HashMap<u32, u32>) {
        self.history.insert(0, PmanDatabaseEntityFields{
            name_id,
            password_id,
            group_id,
            user_id,
            url_id,
            created_at: get_current_timestamp(),
            properties,
        });
    }
    
    pub fn set_database_file(&mut self, database_file: Arc<Mutex<PmanDatabaseFile>>) {
        self.database_file = Some(database_file);
    }

    pub fn collect_names_ids(&self) -> Vec<u32> {
        let mut result = HashSet::new();
        for item in &self.history {
            item.collect_names_ids(&mut result);
        }
        result.into_iter().collect()
    }

    pub fn collect_passwords_ids(&self) -> Vec<u32> {
        let mut result = HashSet::new();
        for item in &self.history {
            item.collect_passwords_ids(&mut result);
        }
        result.into_iter().collect()
    }
}

fn get_current_timestamp() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Error;
    use std::sync::{Arc, Mutex};
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::pman::database_entity::PmanDatabaseEntity;
    use crate::pman::id_value_map::id_value_map::ByteValue;
    use crate::pman::pman_database_file::PmanDatabaseFile;

    #[test]
    fn test_database_entity() -> Result<(), Error> {
        let mut hash1 = [0u8; 32];
        OsRng.fill_bytes(&mut hash1);
        let mut hash2 = [0u8; 32];
        OsRng.fill_bytes(&mut hash2);
        let hash1_vec = Vec::from(hash1);
        let hash2_vec = Vec::from(hash2);
        let db = Arc::new(Mutex::new(PmanDatabaseFile::new(hash1_vec.clone(), hash2_vec.clone())?));
        let mut entity1 = PmanDatabaseEntity::new(db.clone(), 1, 2, 3, 4, None, HashMap::new());
        entity1.update(55, 66, 77, 88, Some(99),
                       HashMap::from([(110, 111), (112, 113)]));
        let entity2 = PmanDatabaseEntity::new(db, 5, 6, 7, 8, Some(9),
                                              HashMap::from([(10, 11), (12, 13)]));
        let e1 = PmanDatabaseEntity::from_bytes(entity1.to_bytes())?;
        assert_eq!(entity1.history, e1.history);
        let e2 = PmanDatabaseEntity::from_bytes(entity2.to_bytes())?;
        assert_eq!(entity2.history, e2.history);
        Ok(())
    }
}