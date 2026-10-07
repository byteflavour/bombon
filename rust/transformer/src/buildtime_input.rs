use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use serde::Deserialize;

use crate::derivation::{Derivation, Meta};

#[derive(Clone)]
pub struct BuildtimeInput(pub BTreeMap<String, Derivation>);

impl BuildtimeInput {
    pub fn from_file(path: &Path) -> Result<Self> {
        let buildtime_input_json: Vec<Derivation> = serde_json::from_reader(
            fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?,
        )
        .with_context(|| format!("Failed to parse buildtime input at {}", path.display()))?;
        let mut m = BTreeMap::new();
        for derivation in buildtime_input_json {
            m.insert(derivation.path.clone(), derivation);
        }
        Ok(Self(m))
    }
}

/// The metadata of packages that are built from the same source as a build recipe, by the store
/// path of that recipe.
#[derive(Clone, Default)]
pub struct SameSourceMetadata(BTreeMap<String, SameSource>);

#[derive(Deserialize, Clone)]
struct SameSource {
    meta: Meta,
}

impl SameSourceMetadata {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        Self::from_json(&content)
            .with_context(|| format!("Failed to parse same source metadata at {}", path.display()))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        Ok(Self(serde_json::from_str(json)?))
    }

    pub fn get(&self, recipe: &str) -> Option<&Meta> {
        self.0.get(recipe).map(|same_source| &same_source.meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_source_metadata() -> Result<()> {
        let metadata = SameSourceMetadata::from_json(
            r#"{ "/nix/store/a-vaultwarden.drv": { "meta": { "description": "Password manager", "homepage": "https://example.org" } } }"#,
        )?;

        assert_eq!(
            metadata
                .get("/nix/store/a-vaultwarden.drv")
                .and_then(|meta| meta.description.as_deref()),
            Some("Password manager")
        );
        assert!(metadata.get("/nix/store/b-other.drv").is_none());
        assert!(SameSourceMetadata::from_json("{}")?.get("x").is_none());
        assert!(SameSourceMetadata::from_json("[]").is_err());
        Ok(())
    }
}
