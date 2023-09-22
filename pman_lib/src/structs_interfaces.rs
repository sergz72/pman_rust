use std::collections::HashMap;
use std::io::Error;

pub trait DatabaseEntity {
    fn get_name(&self) -> String;
    fn get_user_id(&self) -> usize;
    fn get_password(&self) -> String;
    fn get_url(&self) -> Option<String>;
    fn get_property_names(&self) -> Vec<String>;
    fn get_property_value(&self, index: usize) -> String;

    fn set_name(&mut self, value: String) -> Result<(), Error>;
    fn set_user_id(&mut self, id: usize) -> Result<(), Error>;
    fn set_password(&mut self, value: String) -> Result<(), Error>;
    fn set_url(&mut self, value: Option<String>) -> Result<(), Error>;
    fn set_property(&mut self, id: usize, value: String) -> Result<(), Error>;
    fn add_property(&mut self, name: String, value: String) -> Result<(), Error>;
    fn delete_property(&mut self, name: String) -> Result<(), Error>;
}

pub struct DatabaseSearchResult {
    pub group_name: String,
    pub entities: Vec<Box<dyn DatabaseEntity>>
}

pub struct DownloadAction {
    url: String,
    headers: Vec<String>
}

impl DownloadAction {
    pub fn get_url(&self) -> String {
        return self.url.clone()
    }

    pub fn get_headers(&self) -> Vec<String> {
        return self.headers.clone()
    }
}

pub struct UploadAction {
    url: String,
    method: String,
    headers: Vec<String>,
    body: Option<Vec<u8>>,
    expected_http_code: usize
}

pub struct SaveAction {
    file_actions: Vec<UploadAction>,
    local_file_contents: Vec<u8>
}

pub trait PasswordDatabase {
    fn is_read_only(&self) -> bool;
    // prepare - validates local file contents.
    fn prepare(&mut self, contents: &Vec<u8>) -> Result<(), Error>;
    // pre_open - tries to decrypt local file and returns download file actions.
    fn pre_open(&mut self, password: String, password2: Option<String>, key_file_contents: &Vec<u8>)
                -> Result<Vec<DownloadAction>, Error>;
    // open - opens database using download results.
    fn open(&mut self, download_result: Vec<&Vec<u8>>) -> Result<(), Error>;
    fn get_users(&self) -> Result<HashMap<usize, String>, Error>;
    fn add_user(&mut self, name: String) -> Result<usize, Error>;
    fn remove_user(&mut self, id: usize) -> Result<(), Error>;
    fn search(&self, search_string: String) -> Result<Vec<DatabaseSearchResult>, Error>;
    fn add_group(&mut self, name: String) -> Result<(), Error>;
    fn delete_group(&mut self, name: String) -> Result<(), Error>;
    fn delete_entity(&mut self, group: String, name: String) -> Result<(), Error>;
    fn add_entity(&mut self, group: String, name: String, user_id: usize, password: String,
                  url: Option<String>, properties: HashMap<String, String>) -> Result<(), Error>;
    fn save(&mut self) -> Result<SaveAction, Error>;
}

