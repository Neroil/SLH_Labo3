use casbin::function_map::regex_match;
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zxcvbn::Score::Three;

extern crate zxcvbn;



/// This function checks if the given password is valid
/// Returns true if the password is strong enough, false otherwise
fn password_validation(password: &str, username: &str) -> bool {
    //TODO: Implement password validation
    let estimated_strength = zxcvbn::zxcvbn(password, &[username]);
    estimated_strength.score() >= Three //Hope this works lol
}

/// Interactively prompts the user for a password
pub fn password_input_validation(username: &str) -> String {
    //TODO: Implement password input validation
    loop {
        eprintln!("Please enter a password.");
        let password = inquire::Password::new("Enter your password: ")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
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
    //TODO
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
    todo!()
}