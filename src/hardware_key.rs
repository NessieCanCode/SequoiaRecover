#[cfg(feature = "hardware-auth")]
use yubikey::{MgmKey, YubiKey};

#[cfg(feature = "hardware-auth")]
const OBJECT_ID: yubikey::ObjectId = 0x005f_ff10;

#[cfg(feature = "hardware-auth")]
pub fn store_key(key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut yk = YubiKey::open()?;
    yk.authenticate(MgmKey::default())?;
    let mut data = key.to_vec();
    yk.save_object(OBJECT_ID, &mut data)?;
    Ok(())
}

#[cfg(feature = "hardware-auth")]
pub fn load_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut yk = YubiKey::open()?;
    yk.authenticate(MgmKey::default())?;
    let data = yk.fetch_object(OBJECT_ID)?;
    Ok(data.to_vec())
}

#[cfg(not(feature = "hardware-auth"))]
pub fn store_key(_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    Err("hardware-auth feature disabled".into())
}

#[cfg(not(feature = "hardware-auth"))]
pub fn load_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Err("hardware-auth feature disabled".into())
}
