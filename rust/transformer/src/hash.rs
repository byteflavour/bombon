use std::fmt::Write;
use std::str::FromStr;

use anyhow::{Error, Result, anyhow, bail};
use base64::prelude::{BASE64_STANDARD, Engine as _};

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct SriHash {
    pub algorithm: Algorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl FromStr for SriHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parsed = s.trim().split('-');

        let algorithm: Algorithm = parsed
            .next()
            .and_then(|s| FromStr::from_str(s).ok())
            .ok_or(anyhow!("Failed to parse hash algorithm"))?;

        let digest = parsed
            .next()
            .and_then(|s| BASE64_STANDARD.decode(s).ok())
            .ok_or(anyhow!("Failed to decode hash digest"))?;

        Ok(Self { algorithm, digest })
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let matched = match s {
            "md5" => Self::Md5,
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            "sha512" => Self::Sha512,
            _ => bail!("Failed to parse hash algorithm"),
        };
        Ok(matched)
    }
}

impl SriHash {
    /// Create an `SriHash` from the name of an algorithm and a hex encoded digest.
    pub fn from_hex(algorithm: &str, hex: &str) -> Result<Self> {
        if !hex.is_ascii() || !hex.len().is_multiple_of(2) {
            bail!("Failed to decode hash digest");
        }
        let digest = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| anyhow!("Failed to decode hash digest"))?;

        Ok(Self {
            algorithm: algorithm.parse()?,
            digest,
        })
    }

    /// Return the hash in the SRI format.
    pub fn to_sri(&self) -> String {
        let algorithm = match self.algorithm {
            Algorithm::Md5 => "md5",
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
        };
        format!("{algorithm}-{}", BASE64_STANDARD.encode(&self.digest))
    }

    /// Return the digest as a lower hex encoded string.
    pub fn hex_digest(&self) -> String {
        let mut buffer = String::new();
        for byte in &self.digest {
            let _ = write!(&mut buffer, "{byte:02x}");
        }
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sri_from_hex() -> Result<()> {
        let hex = "3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0";
        let hash = SriHash::from_hex("sha256", hex)?;

        assert_eq!(
            hash.to_sri(),
            "sha256-PToblzryGBFPT4ibuqL0wDfequDI6BXuw4HD1Ua5dKA="
        );
        assert_eq!(hash.hex_digest(), hex);
        assert!(SriHash::from_hex("sha256", "3d3").is_err());
        assert!(SriHash::from_hex("sha256", "zz").is_err());
        assert!(SriHash::from_hex("blake3", "3d3a").is_err());
        Ok(())
    }
}
