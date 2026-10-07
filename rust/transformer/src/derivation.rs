use serde::Deserialize;

use crate::buildtime_input::SameSourceMetadata;
use crate::hash::SriHash;
use crate::recipe::{RecipeIndex, RecipeOutput};

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Derivation {
    pub path: String,
    pub name: Option<String>,
    pub pname: Option<String>,
    pub version: Option<String>,
    pub meta: Option<Meta>,
    pub output_name: Option<String>,
    pub output_hash: Option<String>,
    pub src: Option<Src>,
    pub vendored_sbom: Option<String>,
    pub patches: Vec<String>,
    #[serde(default)]
    pub build_references: Vec<String>,
    /// Whether the package only describes a store path, i.e. is not part of the build closure.
    #[serde(default)]
    pub metadata_only: bool,
    /// Where the name and the version come from.
    #[serde(skip)]
    pub identification: Identification,
    /// Whether this is a downloaded file instead of a package.
    #[serde(skip)]
    pub is_file: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Identification {
    /// The package object states the name and the version.
    #[default]
    Package,
    /// The build recipe states the name and the version.
    Recipe,
    /// The build recipe states the name and the version. The metadata is that of a package that
    /// is built from the same source.
    RecipeWithSameSource,
    /// The version is split off the name stated by the build recipe.
    Name,
}

impl Derivation {
    /// Create a `Derivation` from what a build recipe states about a store path.
    ///
    /// This is used for store paths we don't have a package object for. Returns `None` if the
    /// store path is neither a package nor a download.
    pub fn from_recipe(
        store_path: &str,
        output: &RecipeOutput,
        recipes: &RecipeIndex,
        same_source: &SameSourceMetadata,
    ) -> Option<Self> {
        let derivation = Self {
            path: store_path.to_string(),
            output_name: Some(output.output.clone()),
            ..Self::default()
        };

        if let (Some(pname), Some(version)) = (&output.pname, &output.version) {
            // What the recipe states is kept. Only the metadata, which a recipe doesn't contain,
            // is taken from a package that is built from the same source.
            let meta = same_source.get(&output.recipe).cloned();
            return Some(Self {
                identification: if meta.is_some() {
                    Identification::RecipeWithSameSource
                } else {
                    Identification::Recipe
                },
                meta,
                name: output.name.clone(),
                pname: Some(pname.clone()),
                version: Some(version.clone()),
                // The source is only of interest if it is downloaded from somewhere.
                src: output
                    .src
                    .as_ref()
                    .and_then(|src| recipes.get(src))
                    .filter(|src| src.is_download())
                    .map(Src::from_download),
                patches: output.patches.clone(),
                ..derivation
            });
        }

        if output.is_download() {
            return Some(Self {
                name: output.name.clone(),
                src: Some(Src::from_download(output)),
                is_file: true,
                identification: Identification::Recipe,
                ..derivation
            });
        }

        let (name, version) = split_name(output.name.as_deref()?)?;
        Some(Self {
            name: Some(name.to_string()),
            version: Some(version.to_string()),
            identification: Identification::Name,
            ..derivation
        })
    }
}

/// Split the name of a derivation into the name and the version of the package.
///
/// The last part of the name is taken as the version if it starts with a digit.
fn split_name(name: &str) -> Option<(&str, &str)> {
    name.rsplit_once('-')
        .filter(|(name, version)| !name.is_empty() && version.starts_with(char::is_numeric))
}

#[derive(Deserialize, Clone, Debug)]
pub struct Meta {
    pub license: Option<LicenseField>,
    pub homepage: Option<String>,
    pub description: Option<String>,
    pub identifiers: Option<Identifiers>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct Identifiers {
    pub cpe: Option<String>,
    #[serde(rename = "possibleCPEs")]
    pub possible_cpes: Option<Vec<Cpe>>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct Cpe {
    pub cpe: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum LicenseField {
    LicenseList(LicenseList),
    LicenseExpression(LicenseExpression),
    // In very rare cases the license is just a String.
    // This mostly serves as a fallback so that serde doesn't panic.
    String(String),
}

#[derive(Deserialize, Clone, Debug)]
pub struct LicenseList(pub Vec<License>);

#[derive(Deserialize, Clone, Debug)]
pub struct License {
    #[serde(rename = "fullName")]
    pub full_name: String,
    #[serde(rename = "spdxId")]
    pub spdx_id: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct LicenseExpression(pub String);

#[derive(Deserialize, Clone, Debug)]
pub struct Src {
    pub urls: Vec<String>,
    pub hash: Option<String>,
}

impl Src {
    fn from_download(output: &RecipeOutput) -> Self {
        Self {
            urls: output.urls.clone(),
            // The hash of a file tree is not the hash of a file and thus left out.
            hash: output
                .fixed
                .as_ref()
                .filter(|fixed| !fixed.recursive)
                .and_then(|fixed| SriHash::from_hex(&fixed.algorithm, &fixed.digest).ok())
                .map(|hash| hash.to_sri()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use anyhow::{Context, Result};

    use super::*;
    use crate::recipe::tests::{HELLO, LIBSSH2, XZ_TARBALL};

    #[test]
    fn split_names() {
        assert_eq!(
            split_name("oniguruma-6.9.10"),
            Some(("oniguruma", "6.9.10"))
        );
        assert_eq!(
            split_name("mailcap-extra-2.1.54"),
            Some(("mailcap-extra", "2.1.54"))
        );
        assert_eq!(
            split_name("emacs-pgtk-with-packages-31.1"),
            Some(("emacs-pgtk-with-packages", "31.1"))
        );
        assert_eq!(split_name("unit-caddy.service"), None);
        assert_eq!(split_name("fc-53-no-bitmaps.conf"), None);
        assert_eq!(split_name("linux-6.18.54-modules"), None);
        assert_eq!(split_name("system-units"), None);
        assert_eq!(split_name("-1.0"), None);
    }

    fn index(recipes: &[(&str, String)]) -> Result<RecipeIndex> {
        RecipeIndex::from_recipes(
            &recipes
                .iter()
                .map(|(path, text)| ((*path).to_string(), text.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    fn from_recipe(recipes: &RecipeIndex, store_path: &str) -> Result<Option<Derivation>> {
        let output = recipes.get(store_path).context("Missing output")?;
        Ok(Derivation::from_recipe(
            store_path,
            output,
            recipes,
            &SameSourceMetadata::default(),
        ))
    }

    #[test]
    fn recipe_with_same_source_metadata() -> Result<()> {
        let same_source = SameSourceMetadata::from_json(
            r#"{
                "/nix/store/a-libssh2.drv": { "meta": { "description": "A library" } },
                "/nix/store/b-xz.drv": { "meta": { "description": "A tarball" } },
                "/nix/store/c-wrapper.drv": { "meta": { "description": "A wrapper" } }
            }"#,
        )?;
        let recipes = index(&[
            ("/nix/store/a-libssh2.drv", LIBSSH2.into()),
            ("/nix/store/b-xz.drv", XZ_TARBALL.into()),
            (
                "/nix/store/c-wrapper.drv",
                HELLO.replace("\\\"pname\\\":\\\"hello\\\",", ""),
            ),
        ])?;
        let from_recipe = |path: &str| -> Result<Derivation> {
            let output = recipes.get(path).context("Missing output")?;
            Derivation::from_recipe(path, output, &recipes, &same_source)
                .context("Missing derivation")
        };

        // The metadata is added to what the recipe states.
        let package =
            from_recipe("/nix/store/b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev")?;
        assert_eq!(package.identification, Identification::RecipeWithSameSource);
        assert_eq!(package.pname.as_deref(), Some("libssh2"));
        assert_eq!(package.version.as_deref(), Some("1.11.1"));
        assert_eq!(package.patches.len(), 1);
        assert_eq!(
            package.meta.and_then(|meta| meta.description).as_deref(),
            Some("A library")
        );

        // Neither files nor packages whose version is split off a name get any.
        let file = from_recipe("/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz")?;
        assert!(file.is_file);
        assert!(file.meta.is_none());
        let named = from_recipe("/nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3")?;
        assert_eq!(named.identification, Identification::Name);
        assert!(named.meta.is_none());
        Ok(())
    }

    #[test]
    fn recipe_states_name_and_version() -> Result<()> {
        let recipes = index(&[
            ("/nix/store/a-libssh2.drv", LIBSSH2.into()),
            (
                "/nix/store/b-libssh2-src.drv",
                XZ_TARBALL.replace(
                    "/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz",
                    "/nix/store/j04yfblg6sk5abb4n067xv0x0dfraf73-libssh2-1.11.1.tar.gz",
                ),
            ),
        ])?;
        let path = "/nix/store/b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev";
        let derivation = from_recipe(&recipes, path)?.context("Missing derivation")?;

        assert_eq!(derivation.path, path);
        assert_eq!(derivation.pname.as_deref(), Some("libssh2"));
        assert_eq!(derivation.version.as_deref(), Some("1.11.1"));
        assert_eq!(derivation.output_name.as_deref(), Some("dev"));
        assert_eq!(derivation.identification, Identification::Recipe);
        assert!(!derivation.is_file);
        assert_eq!(
            derivation.patches,
            ["/nix/store/m9171q7kn5bbp08hqmhfra41mmn6p5nk-CVE-2026-7598.patch"]
        );
        let src = derivation.src.context("Missing source")?;
        assert_eq!(src.urls, ["https://tukaani.org/xz/xz-5.8.3.tar.gz"]);
        assert_eq!(
            src.hash.as_deref(),
            Some("sha256-PToblzryGBFPT4ibuqL0wDfequDI6BXuw4HD1Ua5dKA=")
        );
        Ok(())
    }

    #[test]
    fn recipe_with_structured_attributes() -> Result<()> {
        let recipes = index(&[("/nix/store/a-hello.drv", HELLO.into())])?;
        let derivation = from_recipe(
            &recipes,
            "/nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3",
        )?
        .context("Missing derivation")?;

        assert_eq!(derivation.pname.as_deref(), Some("hello"));
        assert_eq!(derivation.version.as_deref(), Some("2.12.3"));
        // The recipe of the source is not known, so it can't be a download.
        assert!(derivation.src.is_none());
        Ok(())
    }

    #[test]
    fn recipe_is_a_download() -> Result<()> {
        let path = "/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz";

        let recipes = index(&[("/nix/store/a-xz.drv", XZ_TARBALL.into())])?;
        let derivation = from_recipe(&recipes, path)?.context("Missing derivation")?;
        assert!(derivation.is_file);
        assert_eq!(derivation.name.as_deref(), Some("xz-5.8.3.tar.gz"));
        assert_eq!(derivation.version, None);
        assert_eq!(derivation.pname, None);
        let src = derivation.src.context("Missing source")?;
        assert_eq!(src.urls, ["https://tukaani.org/xz/xz-5.8.3.tar.gz"]);
        assert!(src.hash.is_some());

        // A downloaded file tree has no file hash.
        let recipes = index(&[(
            "/nix/store/a-xz.drv",
            XZ_TARBALL.replace("\"sha256\"", "\"r:sha256\""),
        )])?;
        let derivation = from_recipe(&recipes, path)?.context("Missing derivation")?;
        assert!(derivation.is_file);
        assert!(derivation.src.is_some_and(|src| src.hash.is_none()));

        // A download that states its name and version is a package.
        let recipes = index(&[(
            "/nix/store/a-xz.drv",
            XZ_TARBALL.replace(
                "(\"preferLocalBuild\",\"1\")",
                "(\"pname\",\"xz\"),(\"version\",\"5.8.3\")",
            ),
        )])?;
        let derivation = from_recipe(&recipes, path)?.context("Missing derivation")?;
        assert!(!derivation.is_file);
        assert_eq!(derivation.pname.as_deref(), Some("xz"));
        assert_eq!(derivation.version.as_deref(), Some("5.8.3"));
        Ok(())
    }

    #[test]
    fn recipe_states_only_a_name() -> Result<()> {
        let without_version = |name: &str| {
            HELLO.replace("\\\"pname\\\":\\\"hello\\\",", "").replace(
                "\\\"name\\\":\\\"hello-2.12.3\\\"",
                &format!("\\\"name\\\":\\\"{name}\\\""),
            )
        };
        let path = "/nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3";

        let recipes = index(&[(
            "/nix/store/a-wrapper.drv",
            without_version("emacs-pgtk-with-packages-31.1"),
        )])?;
        let derivation = from_recipe(&recipes, path)?.context("Missing derivation")?;
        assert_eq!(derivation.name.as_deref(), Some("emacs-pgtk-with-packages"));
        assert_eq!(derivation.version.as_deref(), Some("31.1"));
        assert_eq!(derivation.identification, Identification::Name);
        assert!(derivation.patches.is_empty());

        let recipes = index(&[(
            "/nix/store/a-unit.drv",
            without_version("unit-caddy.service"),
        )])?;
        assert!(from_recipe(&recipes, path)?.is_none());
        Ok(())
    }
}
