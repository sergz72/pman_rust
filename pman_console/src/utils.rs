use std::fs::File;
use std::io::{Error, ErrorKind, Read, Write};
use passterm::prompt_password_tty;
use rand::Rng;

const LETTER_TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const NUMBER_TABLE: &str = "0123456789";
const SYMBOL_TABLE: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

pub fn generate_password(rules: String) -> String {
    let l = rules.len();
    if let Ok(length) = rules[l-2..l].parse::<usize>() {
        let mut table = String::new();
        for c in rules[3..l-2].chars() {
            match c {
                'a' => table += LETTER_TABLE,
                '1' => table += NUMBER_TABLE,
                '@' => table += SYMBOL_TABLE,
                _ => return rules
            }
        }
        let chars: Vec<char> = table.chars().collect();
        let mut result = String::new();
        let mut rng = rand::thread_rng();
        for _ in 0..length {
            let idx = rng.gen_range(0..chars.len());
            result.push(chars[idx]);
        }
        println!("Generated password: {}", result);
        return result;
    }
    rules
}

pub fn parse_string_array(array: String, error_message: &str, expected_count: Option<usize>) -> Result<Vec<String>, Error> {
    if array.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, error_message));
    }
    let result: Vec<String> = array.split(',').map(|v|v.to_string()).collect();
    if let Some(count) = expected_count {
        if result.len() != count {
            return Err(Error::new(ErrorKind::InvalidInput,
                                  format!("{} items in {}", count, error_message)));
        }
    }
    Ok(result)
}

pub fn load_file(file_name: String) -> Result<Vec<u8>, Error> {
    let mut f = File::open(file_name)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(data)
}

pub fn load_files(file_names: Vec<String>) -> Result<Vec<Vec<u8>>, Error> {
    let mut result = Vec::new();
    for file_name in file_names {
        result.push(load_file(file_name)?);
    }
    Ok(result)
}

pub fn create_file(file_name: &String, data: Vec<u8>) -> Result<(), Error> {
    let mut f = File::create(file_name)?;
    f.write_all(data.as_slice())
}

pub fn get_password(prompt: &str, password: String) -> Result<String, Error> {
    if !password.is_empty() {
        return Ok(password);
    }
    prompt_password_tty(Some(prompt))
        .map_err(|e|Error::new(ErrorKind::Other, e.to_string()))
}
