use std::error::Error;

use aes_gcm::{
    aead::{generic_array::functional::FunctionalSequence, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

fn encrypt(cipher: &Aes256Gcm, creds: &str) -> (Vec<u8>, Vec<u8>) {
    // TODO: generate randomly for each use
    // Note that this nonce can be stored directly in DB without encryption
    let nonce = Nonce::from_slice(b"unique nonce");

    let encrypted_credentials = cipher.encrypt(nonce, creds.as_ref()).unwrap();

    return (<&[u8]>::from(nonce).into(), encrypted_credentials.into());
}

fn main() -> Result<(), Box<dyn Error>> {
    // Generate like this -- can be stored
    let key = Aes256Gcm::generate_key(&mut OsRng);

    // Serialization -- althrough it looks wonky (can be base64-ed?)
    let key_serialized: String = key
        .fold(Vec::<char>::new(), |mut acc, v| -> Vec<char> {
            acc.push(v.into());
            acc
        })
        .into_iter()
        .collect();
    println!("Wonkey serialized key -> {}", key_serialized);
    let cipher = Aes256Gcm::new(&key);

    let creds = "oh noes top secret";
    let (nonce, encrypted) = encrypt(&cipher, &creds);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce.as_ref()), encrypted.as_ref())
        .unwrap();
    assert_eq!(&plaintext, creds.as_bytes());
    println!(
        "credentials leak: {}",
        plaintext
            .into_iter()
            .map(|u| char::from(u))
            .collect::<String>()
    );
    Ok(())
}
