#[cfg(feature = "hardware-auth")]
use yubikey::{piv::ObjectId, YubiKey};

#[cfg(feature = "hardware-auth")]
use rand::{rngs::OsRng, RngCore};
#[cfg(feature = "hardware-auth")]
use std::error::Error;

#[cfg(feature = "hardware-auth")]
const KEY_OBJECT_ID: ObjectId = 0x005f_ff10;

#[cfg(feature = "hardware-auth")]
pub fn store_key(key: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut yubikey = YubiKey::open()?;
    let mut data = key.to_vec();
    yubikey.save_object(KEY_OBJECT_ID, &mut data)?;
    Ok(())
}

#[cfg(feature = "hardware-auth")]
pub fn load_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut yubikey = YubiKey::open()?;
    let buf = yubikey.fetch_object(KEY_OBJECT_ID)?;
    Ok(buf.to_vec())
}

#[cfg(feature = "hardware-auth")]
pub fn get_or_create() -> Result<[u8; 32], Box<dyn Error>> {
    match load_key() {
        Ok(data) => {
            if data.len() != 32 {
                return Err("invalid key length".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            Ok(key)
        }
        Err(_) => {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            store_key(&key)?;
            Ok(key)
        }
    }
}

#[cfg(not(feature = "hardware-auth"))]
pub fn store_key(_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    Err("hardware-auth feature not enabled".into())
}

#[cfg(not(feature = "hardware-auth"))]
pub fn load_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Err("hardware-auth feature not enabled".into())
}

#[cfg(not(feature = "hardware-auth"))]
pub fn get_or_create() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Err("hardware-auth feature not enabled".into())
}
