use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher};

#[cfg(feature = "build")]
use rand_core::OsRng;

/// Hash a password with provided base64 string
pub fn hash_password_from_b64(password: &[u8], salt: &str) -> Result<String, String> {
    let salt = SaltString::from_b64(salt).map_err(|e| e.to_string())?;
    hash_password_with_salt(password, &salt)
}

/// Hash a password with pre-generated salt.
pub fn hash_password_with_salt(password: &[u8], salt: &SaltString) -> Result<String, String> {
    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // hash password
    let password_hash = argon2
        .hash_password(password, salt)
        .map_err(|e| e.to_string())?
        .to_string();

    // verify password
    let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| e.to_string())?;
    Ok(parsed_hash.to_string())
}

/// Hash a password with a randomly-generated salt.
#[cfg(feature = "build")]
pub fn hash_password(password: &[u8]) -> Result<(String, String), String> {
    // generate password salt
    let salt = SaltString::generate(&mut OsRng);

    // hash password
    let pass_hash = hash_password_with_salt(password, &salt)?;
    Ok((salt.to_string(), pass_hash))
}
