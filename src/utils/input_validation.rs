use casbin::function_map::regex_match;
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zxcvbn::Score::Three;

extern crate zxcvbn;

//Needed for the tests in authorization.rs
impl Username {
    pub fn new(username: String) -> Username {
        Username(username)
    }
}

/// This function checks if the given password is valid
/// Returns true if the password is strong enough, false otherwise
fn password_validation(password: &str, username: &str) -> bool {
    let estimated_strength = zxcvbn::zxcvbn(password, &[username]);
    estimated_strength.score() >= Three
}

/// Interactively prompts the user for a password
pub fn password_input_validation(username: &str) -> String {
    loop {
        eprintln!("Please enter a password.");
        let password = inquire::Password::new("Enter your password: ")
            .prompt()
            .unwrap();

        if password_validation(&password, username) {
            return password;
        } else {
            eprintln!("Password is too weak. Please try again.");
        }
    }
}

#[derive(Debug, Clone, Copy, Display, Error)]
pub struct InvalidInput;

/// Wrapper type for a username thas has been validated
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
pub struct Username(String);

impl TryFrom<String> for Username {
    type Error = InvalidInput;

    fn try_from(username: String) -> Result<Self, Self::Error> {
        username_validation(&username)?;
        Ok(Self(username))
    }
}

impl TryFrom<&str> for Username {
    type Error = InvalidInput;

    fn try_from(username: &str) -> Result<Self, Self::Error> {
        username_validation(username)?;
        Ok(Self(username.to_owned()))
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn username_validation(username: &str) -> Result<(), InvalidInput> {
    if username.len() < 3 || username.len() > 30 || regex_match(r"^[a-zA-Z0-9_-]+$",username){
        return Err(InvalidInput);
    }
    Ok(())
}

pub fn username_input_validation(message: &str) -> Result<Username, InvalidInput> {
    //TODO
    loop {
        let username = inquire::Text::new(message)
            .prompt()
            .unwrap();

        if username_validation(&username).is_ok() {
            return username.try_into();
        } else {
            eprintln!("Invalid username. Please try again. \
            \nUsername must be between 3 and 30 characters long and can only contain letters, numbers, underscores and hyphens.");
        }
    }
}

/// Wrapper type for an AVS number that has been validated
#[derive(Debug, Display, Serialize, Deserialize, Hash)]
pub struct AVSNumber(String);

impl TryFrom<String> for AVSNumber {
    type Error = InvalidInput;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if validate_avs_number(&value) {
            Ok(AVSNumber(value))
        } else {
            Err(InvalidInput)
        }
    }
}

fn validate_avs_number(avs_number: &str) -> bool {

    //Check if the AVS number starts with 756
    if(avs_number.chars().take(3).collect::<String>() != "756"){
        return false;
    }
    //Remove the dots
    let avs_number_no_dot = avs_number.replace(".","");
    
    gtin_validate::gtin13::check(&avs_number_no_dot)
    
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_password(){
        
        
    }

    #[test]
    fn test_validate_avs_number() {
        // Valid AVS numbers
        assert!(validate_avs_number("756.1234.5678.97"));
        assert!(validate_avs_number("756.0905.7171.04"));
        assert!(validate_avs_number("7561234567897"));

        // Invalid AVS numbers
        assert!(!validate_avs_number("123.4567.8901.23"));
        assert!(!validate_avs_number("756.0905.7171.05"));
        assert!(!validate_avs_number("756.1234.5678.98"));
        assert!(!validate_avs_number("invalid_avs_number"));
    }
}