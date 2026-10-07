use std::fs::File;
use std::io::Write;
use std::path::Path;

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

#[allow(clippy::too_many_arguments)]
pub fn transform(
    include_buildtime_dependencies: bool,
    exclude: &[String],
    serial_number_seed: &str,
    recipes_path: &Path,
    same_source_metadata_path: &Path,
    target_path: &str,
    buildtime_input_path: &Path,
    runtime_input_path: &Path,
    output: &Path,
) -> Result<()> {
    let buildtime_input = BuildtimeInput::from_file(buildtime_input_path)?;
    let target_derivation = buildtime_input
        .0
        .get(target_path)
        .map(ToOwned::to_owned)
        .with_context(|| {
            format!("Buildtime input doesn't contain target derivation: {target_path}")
        })?;

    let runtime_input = RuntimeInput::from_file(runtime_input_path)?;
    let recipes = RecipeIndex::from_file(recipes_path)?;
    let same_source = SameSourceMetadata::from_file(same_source_metadata_path)?;

    let runtime_derivations =
        runtime_derivations(&runtime_input, &buildtime_input, &recipes, &same_source);

    let buildtime_derivations = buildtime_input
        .0
        .clone()
        .into_values()
        .filter(|derivation| !runtime_input.paths.contains(&derivation.path))
        .unique_by(|d| d.name.clone().unwrap_or(d.path.clone()));

    let all_derivations: Box<dyn Iterator<Item = Derivation>> = if include_buildtime_dependencies {
        Box::new(runtime_derivations.chain(buildtime_derivations))
    } else {
        Box::new(runtime_derivations)
    };

    let set = RegexSet::new(exclude).context("Failed to build regex set from exclude patterns")?;

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
        include_buildtime_dependencies,
        vendored_dependencies,
    );

    let bom = CycloneDXBom::build(
        target_derivation,
        components,
        dependencies,
        serial_number_seed,
    );
    let mut file = File::create(output)
        .with_context(|| format!("Failed to create file {}", output.display()))?;
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
