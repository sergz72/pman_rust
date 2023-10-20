use std::collections::HashMap;
use std::io::Error;
use crate::pman::id_value_map::id_value_map::ByteValue;

pub struct PmanDatabaseEntityFields {
    group_id: u32,
    user_id: u32,
    url: Option<u32>,
    created_at: u64,
    // map property name id (in names file) -> property value id (in passwords file)
    properties: HashMap<u32, u32>,
}

pub struct PmanDatabaseEntity {
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

impl PmanDatabaseEntity {
    pub fn new(group_id: u32, user_id: u32, url: Option<u32>, properties: HashMap<u32, u32>) -> PmanDatabaseEntity {
        PmanDatabaseEntity{history: vec![PmanDatabaseEntityFields{
            group_id,
            user_id,
            url,
            created_at: get_current_timestamp(),
            properties,
        }]}
    }

    pub fn update(&mut self, group_id: u32, user_id: u32, url: Option<u32>, properties: HashMap<u32, u32>) {
        self.history.insert(0, PmanDatabaseEntityFields{
            group_id,
            user_id,
            url,
            created_at: get_current_timestamp(),
            properties,
        });
    }

    pub fn get_group_id(&self) -> u32 {
        self.history.get(0).unwrap().group_id
    }

    pub fn get_user_id(&self) -> u32 {
        self.history.get(0).unwrap().user_id
    }
}

fn get_current_timestamp() -> u64 {
    todo!()
}