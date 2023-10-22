use std::collections::HashMap;
use std::io::Error;
use std::sync::{Arc, Mutex};
use crate::pman::id_value_map::id_value_map::ByteValue;
use crate::pman::pman_database_file::PmanDatabaseFile;
use crate::structs_interfaces::PasswordDatabaseEntity;

pub struct PmanDatabaseEntityFields {
    name_id: u32,
    password_id: u32,
    group_id: u32,
    user_id: u32,
    url: Option<u32>,
    created_at: u64,
    // map property name id (in names file) -> property value id (in passwords file)
    properties: HashMap<u32, u32>,
}

pub struct PmanDatabaseEntity {
    database_file: Arc<Mutex<PmanDatabaseFile>>,
    history: Vec<PmanDatabaseEntityFields>
}

impl ByteValue for PmanDatabaseEntity {
    fn from_bytes(source: Vec<u8>) -> Result<Box<PmanDatabaseEntity>, Error> {
        todo!()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.history.len() as u8);
        for item in &self.history {

        }
        //todo
        result
    }
}

impl PasswordDatabaseEntity for PmanDatabaseEntity {
    fn get_name(&self) -> Result<String, Error> {
        let name_id = self.history.get(0).unwrap().name_id;
        self.database_file.lock().unwrap().get_from_names_file(name_id)
    }

    fn get_user_id(&self) -> u32 {
        self.history.get(0).unwrap().user_id
    }

    fn get_group_id(&self) -> u32 {
        self.history.get(0).unwrap().group_id
    }

    fn get_password(&self) -> Result<String, Error> {
        todo!()
    }

    fn get_url(&self) -> Result<Option<String>, Error> {
        todo!()
    }

    fn get_property_names(&self) -> Result<HashMap<u32, String>, Error> {
        todo!()
    }

    fn get_property_value(&self, index: u32) -> Result<String, Error> {
        todo!()
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
               user_id: u32, url: Option<u32>, properties: HashMap<u32, u32>) -> PmanDatabaseEntity {
        PmanDatabaseEntity{database_file, history: vec![PmanDatabaseEntityFields{
            name_id,
            password_id,
            group_id,
            user_id,
            url,
            created_at: get_current_timestamp(),
            properties,
        }]}
    }

    pub fn update(&mut self, name_id: u32, password_id: u32, group_id: u32, user_id: u32,
                  url: Option<u32>, properties: HashMap<u32, u32>) {
        self.history.insert(0, PmanDatabaseEntityFields{
            name_id,
            password_id,
            group_id,
            user_id,
            url,
            created_at: get_current_timestamp(),
            properties,
        });
    }
}

fn get_current_timestamp() -> u64 {
    todo!()
}