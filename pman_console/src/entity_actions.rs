use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use pman_lib::{add_entity, DatabaseEntity, get_entities, get_groups, get_users, modify_entity, remove_entity, search};
use pman_lib::pman::database_entity::ENTITY_VERSION_LATEST;
use pman_lib::structs_interfaces::DatabaseGroup;
use crate::{get_password, Parameters};
use crate::utils::{parse_string_array, generate_password, load_file};

pub fn show_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let users = get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let (entities, groups) = get_entities_from_names(database, entity_names)?;
    for (_, entity) in entities {
        show_entity(&groups, &users, entity)?;
    }
    Ok(false)
}

pub fn show_entity_properties(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let mut entity_names = Vec::new();
    let mut property_names = Vec::new();
    for name in get_entity_names(parameters)? {
        let name_prop_name: Vec<&str> = name.split('@').collect();
        if name_prop_name.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, "entity name should be in format name@property_name"))
        }
        entity_names.push(name_prop_name[0].to_string());
        property_names.push(name_prop_name[1].to_string());
    }
    let (entities, _) = get_entities_from_names(database, entity_names)?;
    for i in 0..entities.len() {
        let pnames = entities[i].1.get_property_names(ENTITY_VERSION_LATEST)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        if let Some(id) = pnames.get(&property_names[i]) {
            let value = entities[i].1.get_property_value(ENTITY_VERSION_LATEST, *id)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            print!("{}", value);
        } else {
            return Err(Error::new(ErrorKind::InvalidInput, "unknown property name"));
        }
    }
    Ok(false)
}

pub fn search_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let groups: HashMap<u32, String> = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .into_iter()
        .map(|g|(g.id, g.name.clone()))
        .collect();
    for name in entity_names {
        let result = search(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        for (group_id, entities) in result {
            println!("{}:", groups.get(&group_id).unwrap());
            for (_, entity) in entities {
                println!("  {}",
                         entity.get_name()
                             .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?)
            }
        }
    }
    Ok(false)
}

pub fn modify_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let (entities, _) = get_entities_from_names(database, entity_names)?;
    let l = entities.len();
    let passwords = if !parameters.entity_passwords_parameter.get_value().is_empty() {
        Some(get_entity_passwords(parameters, Some(l))?)
    } else {None};
    let urls = if !parameters.entity_urls_parameter.get_value().is_empty() {
        Some(get_entity_urls(parameters, Some(l))?)
    } else {None};
    let params = if !parameters.entity_properties_parameter.get_value().is_empty() {
        Some(get_entity_parameters(parameters, Some(l))?)
    } else {None};
    for i in 0..l {
        let password = if let Some(pwds) = &passwords {
            Some(get_entity_password(pwds[i].clone(), i)?)
        } else {None};
        let (url, change_url) = if let Some(u) = &urls {
            (u[i].clone(), true)
        } else {(None, false)};
        let (new_properties, modified_properties) =
            if let Some(p) = &params {
                build_property_maps(entities[i].1.clone(), p[i].clone())?
            } else {(HashMap::new(), HashMap::new())};
        modify_entity(database, entities[i].0, None, None,
                      password, url, change_url, new_properties,
                      modified_properties)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn build_property_maps(entity: Arc<DatabaseEntity>, parameters: HashMap<String, String>)
                       -> Result<(HashMap<String, String>, HashMap<u32, Option<String>>), Error> {
    let property_names = entity.get_property_names(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let mut new_properties = HashMap::new();
    let mut modified_properties = HashMap::new();
    for (name, value) in parameters {
        if let Some(id) = property_names.get(&name) {
            let v = if value == "None" { None } else { Some(value) };
            modified_properties.insert(*id, v);
        } else {
            new_properties.insert(name, value);
        }
    }
    Ok((new_properties, modified_properties))
}

pub fn remove_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let (entities, _) = get_entities_from_names(database, entity_names)?;
    for (entity_id, _) in entities {
        remove_entity(database, entity_id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn get_entities_from_names(database: u64, entity_names: Vec<String>)
                           -> Result<(Vec<(u32, Arc<DatabaseEntity>)>, Vec<Arc<DatabaseGroup>>), Error> {
    let names_set: HashSet<String> = entity_names.into_iter().collect();
    let groups = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let mut entities = Vec::new();
    for group in &groups {
        for (id, entity) in get_entities(database, group.id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?{
            if names_set.contains(&entity.get_name().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?) {
                entities.push((id, entity));
            }
        }
    }
    Ok((entities, groups))
}

fn get_entity_names(parameters: &Parameters) -> Result<Vec<String>, Error> {
    parse_string_array(parameters.entity_names_parameter.get_value(),
                       "entity names expected", None)
}

fn get_entity_passwords(parameters: &Parameters, l: Option<usize>) -> Result<Vec<String>, Error> {
    parse_string_array(parameters.entity_passwords_parameter.get_value(),
                       "entity passwords expected", l)
}

fn get_entity_urls(parameters: &Parameters, l: Option<usize>) -> Result<Vec<Option<String>>, Error> {
    let urls = parse_string_array(parameters.entity_urls_parameter.get_value(),
                                  "entity urls expected", l)?;
    Ok(urls.into_iter().map(|u|if u == "None" {None} else {Some(u)}).collect())
}

fn get_entity_parameters(parameters: &Parameters, l: Option<usize>) -> Result<Vec<HashMap<String, String>>, Error> {
    let params = parse_string_array(parameters.entity_properties_parameter.get_value(),
                                    "entity parameters expected", l)?;
    let mut result = Vec::new();
    for p in params {
        let mut entity_parameters = HashMap::new();
        if p != "None" {
            for part in p.split(';') {
                let namevalue: Vec<String> = part.split(':').map(|e| e.to_string()).collect();
                if namevalue.len() != 2 {
                    return Err(Error::new(ErrorKind::InvalidInput, "invalid parameters"));
                }
                let value = if namevalue[1] == "Ask" {
                    get_password(format!("value for parameter {}: ", namevalue[0]).as_str(), "".to_string())?
                } else if namevalue[1].starts_with("file#") {
                    let data = load_file(namevalue[1][5..].to_string())?;
                    String::from_utf8(data).map_err(|_e|Error::new(ErrorKind::InvalidData, "non-text file"))?
                } else {namevalue[1].clone()};
                entity_parameters.insert(namevalue[0].clone(), value);
            }
        }
        result.push(entity_parameters);
    }
    Ok(result)
}

pub fn get_entity_password(password: String, i: usize) -> Result<String, Error> {
    if password == "Ask" {
        get_password(format!("password for entity {}: ", i).as_str(), "".to_string())
    } else if password.starts_with("gen") && password.len() > 5 {
        Ok(generate_password(password))
    } else {Ok(password)}
}

pub fn add_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let l = Some(entity_names.len());
    let entity_groups =
        parse_string_array(parameters.entity_groups_parameter.get_value(), "entity groups expected", l)?;
    let entity_users =
        parse_string_array(parameters.entity_users_parameter.get_value(), "entity users expected", l)?;
    let entity_passwords = get_entity_passwords(parameters, l)?;
    let entity_urls = get_entity_urls(parameters, l)?;
    let params = if !parameters.entity_properties_parameter.get_value().is_empty() {
        Some(get_entity_parameters(parameters, l)?)
    } else {None};
    let groups: HashMap<String, u32> = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .into_iter()
        .map(|g|(g.name.clone(), g.id))
        .collect();
    let users: HashMap<String, u32> = get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .into_iter()
        .map(|(k, v)|(v, k))
        .collect();
    let mut entity_group_ids = Vec::new();
    let mut entity_user_ids = Vec::new();
    for i in 0..l.unwrap() {
        let group_id = *groups.get(&entity_groups[i]).ok_or(Error::new(ErrorKind::NotFound, "group not found"))?;
        let user_id = *users.get(&entity_users[i]).ok_or(Error::new(ErrorKind::NotFound, "user not found"))?;
        entity_group_ids.push(group_id);
        entity_user_ids.push(user_id);
    }
    for i in 0..l.unwrap() {
        let password = get_entity_password(entity_passwords[i].clone(), i)?;
        let properties = if let Some(p) = &params {
            p[i].clone()
        } else { HashMap::new() };
        add_entity(database, entity_names[i].clone(), entity_group_ids[i],
                   entity_user_ids[i], password, entity_urls[i].clone(), properties)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn show_entity(groups: &Vec<Arc<DatabaseGroup>>, users: &HashMap<u32, String>,
               entity: Arc<DatabaseEntity>) -> Result<(), Error> {
    println!("Name: {}", entity.get_name()
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?);
    let group_id = entity.get_group_id(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let group = groups.iter()
        .find(|g|g.id == group_id).unwrap().name.clone();
    println!("Group: {}", group);
    let user_id = entity.get_user_id(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    println!("User: {}", users.get(&user_id).unwrap().clone());
    let url = entity.get_url(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .unwrap_or("None".to_string());
    println!("Url: {}", url);
    println!("Password: {}", entity.get_password(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?);
    println!("Properties:");
    for (name, id) in entity.get_property_names(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
        let value = entity.get_property_value(ENTITY_VERSION_LATEST, id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        println!("{}:{}", name, value);
    }
    println!("-------------------------------------");
    Ok(())
}

pub fn select_entities(database: u64, group_names: String) -> Result<bool, Error> {
    let groups = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let users = get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    for name in parse_string_array(group_names, "group names expected", None)? {
        let group = groups.iter()
            .find(|g|g.name == name)
            .ok_or(Error::new(ErrorKind::NotFound, "group not found"))?;
        for (_, entity) in get_entities(database, group.id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
            show_entity(&groups, &users, entity)?;
        }
    }
    Ok(false)
}
