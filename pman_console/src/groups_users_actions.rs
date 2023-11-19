use std::io::{Error, ErrorKind};
use pman_lib::{add_group, add_user, get_groups, get_users};
use crate::utils::parse_string_array;

pub fn select_users(database: u64) -> Result<bool, Error> {
    for (_, name) in get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
        println!("{}", name);
    }
    Ok(false)
}

pub fn select_groups(database: u64) -> Result<bool, Error> {
    for group in get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
        println!("{} {}", group.name, group.entities_count);
    }
    Ok(false)
}

pub fn add_groups(database: u64, group_names: String) -> Result<bool, Error> {
    for name in parse_string_array(group_names, "group names expected", None)? {
        add_group(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

pub fn add_users(database: u64, user_names: String) -> Result<bool, Error> {
    for name in parse_string_array(user_names, "user names expected", None)? {
        add_user(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}
