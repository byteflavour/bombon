use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use itertools::Itertools;
use regex::RegexSet;

use crate::buildtime_input::{BuildtimeInput, SameSourceMetadata};
use crate::cyclonedx::{
    CycloneDXBom, CycloneDXComponents, CycloneDXDependencies, VendoredDependencies,
};
use crate::derivation::Derivation;
use crate::recipe::RecipeIndex;
use crate::runtime_input::RuntimeInput;

/// What to transform and how.
pub struct Options {
    /// Include buildtime dependencies in the SBOM.
    pub include_buildtime_dependencies: bool,
    /// Regex patterns of store paths to exclude from the SBOM.
    pub exclude: Vec<String>,
    /// Data to derive the serial number of the SBOM from.
    pub serial_number_seed: String,
    /// Path to JSON containing the build recipes of the target.
    pub recipes: PathBuf,
    /// Path to JSON containing the metadata of packages that are built from the same source as a
    /// build recipe of the target.
    pub same_source_metadata: PathBuf,
    /// Store path of the target derivation.
    pub target: String,
    /// Path to JSON containing the buildtime input.
    pub buildtime_input: PathBuf,
    /// Path to JSON containing the runtime input.
    pub runtime_input: PathBuf,
    /// Path to write the SBOM to.
    pub output: PathBuf,
}

pub fn transform(options: &Options) -> Result<()> {
    let buildtime_input = BuildtimeInput::from_file(&options.buildtime_input)?;
    let target_derivation = buildtime_input
        .0
        .get(&options.target)
        .map(ToOwned::to_owned)
        .with_context(|| {
            format!(
                "Buildtime input doesn't contain target derivation: {}",
                options.target
            )
        })?;

    let runtime_input = RuntimeInput::from_file(&options.runtime_input)?;
    let recipes = RecipeIndex::from_file(&options.recipes)?;
    let same_source = SameSourceMetadata::from_file(&options.same_source_metadata)?;

    let runtime_derivations =
        runtime_derivations(&runtime_input, &buildtime_input, &recipes, &same_source);

    let all_derivations: Box<dyn Iterator<Item = Derivation>> = if options
        .include_buildtime_dependencies
    {
        Box::new(runtime_derivations.chain(buildtime_derivations(&buildtime_input, &runtime_input)))
    } else {
        Box::new(runtime_derivations)
    };

    let set = RegexSet::new(&options.exclude)
        .context("Failed to build regex set from exclude patterns")?;

    let all_derivations = all_derivations
        .filter(is_component)
        // Filter out derivations that match one of the exclude patterns.
        .filter(|derivation| !set.is_match(&derivation.path));

    let mut components = CycloneDXComponents::from_derivations(all_derivations);

    // Augment the components with those retrieved from the `sbom` passthru attribute of the
    // derivations, preserving the (language-level) dependency edges those SBOMs declare.
    let mut vendored_dependencies = VendoredDependencies::new();
    for derivation in buildtime_input.0.values() {
        if let Some(sbom_path) = &derivation.vendored_sbom {
            vendored_dependencies
                .extend(components.extend_from_directory(sbom_path, &derivation.path)?);
        }
    }

    components.deduplicate();

    let dependencies = CycloneDXDependencies::assemble(
        &components,
        &target_derivation,
        &runtime_input,
        &buildtime_input,
        options.include_buildtime_dependencies,
        vendored_dependencies,
    );

    let bom = CycloneDXBom::build(
        target_derivation,
        components,
        dependencies,
        &options.serial_number_seed,
    );
    let mut file = File::create(&options.output)
        .with_context(|| format!("Failed to create file {}", options.output.display()))?;
    file.write_all(&bom.serialize()?)?;

    Ok(())
}

/// Augment the runtime input with information from the buildtime input.
///
/// The buildtime input, however, is not a strict superset of the runtime input. This has to do
/// with how we query the buildinputs from Nix and how dependencies can "hide" in String Contexts.
/// For store paths missing from the buildtime input, the build recipes are consulted. Store paths
/// that no recipe produces are files that were added to the store directly and are left out.
fn runtime_derivations<'a>(
    runtime_input: &'a RuntimeInput,
    buildtime_input: &'a BuildtimeInput,
    recipes: &'a RecipeIndex,
    same_source: &'a SameSourceMetadata,
) -> impl Iterator<Item = Derivation> + 'a {
    runtime_input.paths.iter().filter_map(|store_path| {
        buildtime_input.0.get(store_path).cloned().or_else(|| {
            recipes.get(store_path).and_then(|output| {
                Derivation::from_recipe(store_path, output, recipes, same_source)
            })
        })
    })
}

/// The derivations of the build closure that are not part of the runtime closure.
///
/// Packages that only describe a dependency are not part of the build closure and thus left out.
fn buildtime_derivations<'a>(
    buildtime_input: &'a BuildtimeInput,
    runtime_input: &'a RuntimeInput,
) -> impl Iterator<Item = Derivation> + 'a {
    buildtime_input
        .0
        .values()
        .filter(|derivation| {
            !derivation.metadata_only && !runtime_input.paths.contains(&derivation.path)
        })
        .cloned()
        .unique_by(|d| d.name.clone().unwrap_or(d.path.clone()))
}

/// Whether a derivation is to be included in the SBOM as a component.
fn is_component(derivation: &Derivation) -> bool {
    // Filter out all doc and man outputs.
    let is_documentation = matches!(derivation.output_name.as_deref(), Some("doc" | "man"));
    // Only downloaded files are included without a version.
    !is_documentation && (derivation.version.is_some() || derivation.is_file)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::derivation::Identification;
    use crate::recipe::tests::LIBSSH2;

    #[test]
    fn sources_of_runtime_derivations() -> Result<()> {
        let with_package = "/nix/store/w5lmwpf3abphzw1wcfy40a3sb2djw9gl-libssh2-1.11.1";
        let with_recipe = "/nix/store/b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev";
        let without_recipe = "/nix/store/shkw4qm9qcw5sc5n1k5jznc83ny02r39-default-builder.sh";

        let runtime_input = RuntimeInput {
            paths: BTreeSet::from([with_package, with_recipe, without_recipe].map(String::from)),
            references: BTreeMap::new(),
        };
        let buildtime_input = BuildtimeInput(BTreeMap::from([(
            with_package.to_string(),
            Derivation {
                path: with_package.to_string(),
                pname: Some("from-package".into()),
                version: Some("1".into()),
                ..Derivation::default()
            },
        )]));
        let recipes = RecipeIndex::from_recipes(&BTreeMap::from([(
            "/nix/store/a-libssh2.drv".to_string(),
            LIBSSH2.to_string(),
        )]))?;

        let same_source = SameSourceMetadata::default();
        let derivations =
            runtime_derivations(&runtime_input, &buildtime_input, &recipes, &same_source)
                .map(|d| (d.path.clone(), d))
                .collect::<BTreeMap<_, _>>();

        // The package object takes precedence over the recipe.
        assert_eq!(
            derivations[with_package].pname.as_deref(),
            Some("from-package")
        );
        assert_eq!(
            derivations[with_package].identification,
            Identification::Package
        );
        assert_eq!(derivations[with_recipe].pname.as_deref(), Some("libssh2"));
        assert_eq!(
            derivations[with_recipe].identification,
            Identification::Recipe
        );
        assert!(!derivations.contains_key(without_recipe));
        Ok(())
    }

    #[test]
    fn buildtime_derivations_of_the_closure() {
        let derivation = |path: &str, metadata_only: bool| Derivation {
            path: path.to_string(),
            name: Some(path.to_string()),
            metadata_only,
            ..Derivation::default()
        };
        let runtime_input = RuntimeInput {
            paths: BTreeSet::from(["/nix/store/a-runtime".to_string()]),
            references: BTreeMap::new(),
        };
        let buildtime_input = BuildtimeInput(
            [
                derivation("/nix/store/a-runtime", false),
                derivation("/nix/store/b-buildtime", false),
                derivation("/nix/store/c-described", true),
            ]
            .into_iter()
            .map(|d| (d.path.clone(), d))
            .collect(),
        );

        let paths = buildtime_derivations(&buildtime_input, &runtime_input)
            .map(|d| d.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, ["/nix/store/b-buildtime"]);
    }

    #[test]
    fn components() {
        let package = Derivation {
            version: Some("1.0".into()),
            output_name: Some("out".into()),
            ..Derivation::default()
        };
        assert!(is_component(&package));
        assert!(is_component(&Derivation {
            output_name: None,
            ..package.clone()
        }));
        for output in ["doc", "man"] {
            assert!(!is_component(&Derivation {
                output_name: Some(output.into()),
                ..package.clone()
            }));
        }
        assert!(!is_component(&Derivation {
            version: None,
            ..package.clone()
        }));
        assert!(is_component(&Derivation {
            version: None,
            is_file: true,
            ..package
        }));
    }
}
