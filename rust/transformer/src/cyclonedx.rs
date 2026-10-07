use std::collections::{BTreeMap, BTreeSet};
use std::convert::Into;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use cyclonedx_bom::external_models::normalized_string::NormalizedString;
use cyclonedx_bom::external_models::spdx::SpdxExpression;
use cyclonedx_bom::external_models::uri::{Purl, Uri};
use cyclonedx_bom::models::attached_text::AttachedText;
use cyclonedx_bom::models::bom::{Bom, UrnUuid};
use cyclonedx_bom::models::code::{Diff, Patch, PatchClassification, Patches};
use cyclonedx_bom::models::component::{Classification, Component, Components, Cpe, Scope};
use cyclonedx_bom::models::component::{
    ComponentEvidence, ConfidenceScore, Identity, IdentityField, Method, Methods, Pedigree,
};
use cyclonedx_bom::models::dependency::{Dependencies, Dependency};
use cyclonedx_bom::models::external_reference::{
    self, ExternalReference, ExternalReferenceType, ExternalReferences,
};
use cyclonedx_bom::models::hash::{Hash, HashAlgorithm, HashValue, Hashes};
use cyclonedx_bom::models::license::{License, LicenseChoice, Licenses};
use cyclonedx_bom::models::metadata::Metadata;
use cyclonedx_bom::models::property::{Properties, Property};
use cyclonedx_bom::models::tool::Tools;
use itertools::Itertools;
use sha2::{Digest, Sha256};

use crate::buildtime_input::BuildtimeInput;
use crate::derivation::{self, Derivation, Identification, Meta, Src};
use crate::hash::{self, SriHash};
use crate::runtime_input::RuntimeInput;

/// Strip the `/nix/store/` prefix to match how component bom-refs are derived from store paths.
fn bom_ref(store_path: &str) -> String {
    store_path
        .strip_prefix("/nix/store/")
        .unwrap_or(store_path)
        .to_string()
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct CycloneDXBom(Bom);

impl CycloneDXBom {
    /// Serialize to JSON as bytes.
    pub fn serialize(self) -> Result<Vec<u8>> {
        let mut output = Vec::<u8>::new();
        self.0.output_as_json_v1_5(&mut output)?;
        Ok(output)
    }

    /// Read a `CycloneDXBom` from a path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let file = fs::File::open(path)?;
        Ok(Self(Bom::parse_from_json(file)?))
    }

    pub fn build(
        target: Derivation,
        components: CycloneDXComponents,
        dependencies: CycloneDXDependencies,
        serial_number_seed: &str,
    ) -> Self {
        Self(Bom {
            components: Some(components.into()),
            dependencies: (!dependencies.0.0.is_empty()).then_some(dependencies.0),
            metadata: Some(metadata_from_derivation(target)),
            // Derive a reproducible serial number from the seed. When the seed is the Nix outPath
            // of the SBOM derivation, this works because the outPath is input addressed and thus
            // reproducible while still being unique to the SBOM.
            serial_number: Some(derive_serial_number(serial_number_seed.as_bytes())),
            ..Bom::default()
        })
    }
}

/// Derive a serial number from some arbitrary data.
///
/// This data is hashed with SHA256 and the first 16 bytes are used to create a UUID to serve as a
/// serial number.
fn derive_serial_number(data: &[u8]) -> UrnUuid {
    let hash = Sha256::digest(data);
    let array: [u8; 32] = hash.into();
    #[allow(clippy::expect_used)]
    let bytes = array[..16]
        .try_into()
        .expect("Failed to extract 16 bytes from SHA256 hash");
    let uuid = uuid::Builder::from_bytes(bytes).into_uuid();
    UrnUuid::from(uuid)
}

/// The components of a BOM, together with the references of those that describe a derivation.
pub struct CycloneDXComponents(Components, BTreeSet<String>);

impl CycloneDXComponents {
    pub fn from_derivations(derivations: impl IntoIterator<Item = Derivation>) -> Self {
        let components: Vec<Component> = derivations
            .into_iter()
            .map(CycloneDXComponent::from_derivation)
            .map(CycloneDXComponent::into)
            .collect();
        let references = components
            .iter()
            .filter_map(|c| c.bom_ref.clone())
            .collect();
        Self(Components(components), references)
    }

    /// Extend the `Components` with components read from multiple BOMs inside a directory.
    ///
    /// Returns the `dependencies` graphs declared by those BOMs, so the (language-level)
    /// edges they carry can be preserved in the aggregate SBOM.
    ///
    /// Each vendored BOM's root (`metadata.component`) describes the same artifact as the owning Nix derivation,
    /// but is never itself emitted as a component. Its bom-ref is therefore remapped to the owning derivation's
    /// bom-ref so the language-level graph connects to the store-path component instead of dangling on a root that nothing references.
    pub fn extend_from_directory(
        &mut self,
        path: impl AsRef<Path>,
        owner_path: &str,
    ) -> Result<VendoredDependencies> {
        let target_ref = bom_ref(owner_path);
        let mut m = BTreeMap::new();
        let mut dependencies = Vec::new();

        // Insert the components from the original SBOM
        for component in self.0.0.clone() {
            let key = component
                .bom_ref
                .clone()
                .unwrap_or_else(|| component.name.to_string());
            m.entry(key).or_insert(component);
        }

        // Add the components from the vendored SBOMs
        for entry in fs::read_dir(&path)
            .with_context(|| format!("Failed to read {}", path.as_ref().display()))?
            .flatten()
        {
            let bom = CycloneDXBom::from_file(entry.path())?;
            let root_ref = bom
                .0
                .metadata
                .as_ref()
                .and_then(|meta| meta.component.as_ref())
                .and_then(|component| component.bom_ref.clone());
            if let Some(components) = &bom.0.components {
                for component in &components.0 {
                    let key = component
                        .bom_ref
                        .clone()
                        .unwrap_or_else(|| component.name.to_string());
                    m.entry(key).or_insert_with(|| component.clone());
                }
            }
            if let Some(deps) = bom.0.dependencies {
                for mut dep in deps.0 {
                    if let Some(root) = &root_ref {
                        if dep.dependency_ref == *root {
                            dep.dependency_ref.clone_from(&target_ref);
                        }
                        for sub in &mut dep.dependencies {
                            if sub == root {
                                sub.clone_from(&target_ref);
                            }
                        }
                    }
                    dependencies.push(dep);
                }
            }
        }

        self.0.0 = m.into_values().collect();
        Ok(VendoredDependencies(dependencies))
    }

    /// The set of references of the components currently held.
    /// Keeps the dependency graph valid: edges to/from absent components are dropped.
    pub fn bom_refs(&self) -> BTreeSet<String> {
        self.0
            .0
            .iter()
            .map(|c| c.bom_ref.clone().unwrap_or_else(|| c.name.to_string()))
            .collect()
    }

    // Deduplicate components.
    //
    // Remove entries with duplicate PURLs, falling back to bom-refs, falling back to the name of
    // the component.
    //
    // Components that describe a derivation are never duplicates of each other, because each of
    // them is a different store path. Their PURL, however, only consists of a name and a
    // version, which the outputs of a derivation and sometimes even different derivations share.
    // They are thus only deduplicated by their bom-ref.
    pub fn deduplicate(&mut self) {
        let components = self
            .0
            .0
            .clone()
            .into_iter()
            .unique_by(|c: &Component| {
                let reference = c.bom_ref.clone().unwrap_or(c.name.to_string());
                if self.1.contains(&reference) {
                    return reference;
                }
                c.purl
                    .as_ref()
                    .map_or(reference, std::string::ToString::to_string)
            })
            .collect();
        self.0.0 = components;
    }
}

impl From<CycloneDXComponents> for Components {
    fn from(value: CycloneDXComponents) -> Self {
        value.0
    }
}

/// The (language-level) dependency edges carried by vendored SBOMs, before they are
/// reconciled against the components that actually end up in the final BOM.
#[derive(Default)]
pub struct VendoredDependencies(Vec<Dependency>);

impl VendoredDependencies {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge in the edges from another set of vendored dependencies.
    pub fn extend(&mut self, other: VendoredDependencies) {
        self.0.extend(other.0);
    }
}

pub struct CycloneDXDependencies(Dependencies);

impl CycloneDXDependencies {
    /// Assemble the `CycloneDX` dependency graph. Three sources of edges are combined:
    ///   - the Nix runtime reference graph (from `exportReferencesGraph`), keyed by store path
    ///   - the Nix build-time reference graph (each derivation's direct build inputs)
    ///   - the language-level graphs carried by the vendored SBOMs, keyed by purl
    ///
    /// Edges are restricted to refs that actually exist in the final BOM, so the graph stays
    /// valid after filtering and deduplication. Entries are merged by ref so no `dependency_ref`
    /// appears twice.
    pub fn assemble(
        components: &CycloneDXComponents,
        target_derivation: &Derivation,
        runtime_input: &RuntimeInput,
        buildtime_input: &BuildtimeInput,
        include_buildtime_dependencies: bool,
        vendored_dependencies: VendoredDependencies,
    ) -> Self {
        let mut present = components.bom_refs();
        present.insert(bom_ref(&target_derivation.path));

        let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (path, references) in &runtime_input.references {
            let dependent = bom_ref(path);
            if !present.contains(&dependent) {
                continue;
            }
            let entry = graph.entry(dependent).or_default();
            for reference in references {
                let dependency = bom_ref(reference);
                if present.contains(&dependency) {
                    entry.insert(dependency);
                }
            }
        }
        if include_buildtime_dependencies {
            for derivation in buildtime_input.0.values() {
                let dependent = bom_ref(&derivation.path);
                if !present.contains(&dependent) {
                    continue;
                }
                let entry = graph.entry(dependent.clone()).or_default();
                for reference in &derivation.build_references {
                    let dependency = bom_ref(reference);
                    if dependency != dependent && present.contains(&dependency) {
                        entry.insert(dependency);
                    }
                }
            }
        }
        for dependency in vendored_dependencies.0 {
            if !present.contains(&dependency.dependency_ref) {
                continue;
            }
            let entry = graph.entry(dependency.dependency_ref).or_default();
            for sub in dependency.dependencies {
                if present.contains(&sub) {
                    entry.insert(sub);
                }
            }
        }

        // Declare every component as a node, including leaves with no dependencies of
        // their own: the CycloneDX spec (as required by BSI TR-03183-2 §5.1) mandates
        // that such components appear as empty elements in the dependency graph.
        for reference in &present {
            graph.entry(reference.clone()).or_default();
        }

        Self(Dependencies(
            graph
                .into_iter()
                .map(|(dependency_ref, dependencies)| Dependency {
                    dependency_ref,
                    dependencies: dependencies.into_iter().collect(),
                })
                .collect(),
        ))
    }
}

struct CycloneDXComponent(Component);

impl CycloneDXComponent {
    fn from_derivation(derivation: Derivation) -> Self {
        let name = match derivation.pname {
            Some(pname) => pname,
            None => derivation.name.unwrap_or_default(),
        };
        let version = derivation.version.unwrap_or_default();
        let mut component = Component::new(
            if derivation.is_file {
                Classification::File
            } else {
                // Classification::Application is used as per specification when the type is not
                // known as is the case for dependencies from Nix
                Classification::Application
            },
            &name,
            &version,
            Some(bom_ref(&derivation.path)),
        );
        component.scope = Some(Scope::Required);
        let mut properties = vec![Property::new(
            "bombon:origin",
            origin(derivation.identification, derivation.is_file),
        )];

        let mut external_references = Vec::new();

        if derivation.is_file {
            // A downloaded file is identified by where it comes from and by its hash. It has
            // neither a version nor a place in a package ecosystem.
            component.version = None;
            if let Some(src) = derivation.src {
                component.hashes = src.hash.as_deref().and_then(convert_hash);
                external_references.extend(src.urls.iter().map(|u| convert_distribution(u)));
            }
        } else {
            component.purl = Purl::new("nix", &name, &version).ok();
            component.hashes = derivation.output_hash.and_then(|s| convert_hash(&s));
            if let Some(src) = derivation.src
                && !src.urls.is_empty()
            {
                external_references.extend(convert_src(&src));
            }
        }

        if derivation.identification == Identification::Name {
            component.evidence = Some(name_to_evidence(&name, &version));
        }

        if let Some(meta) = derivation.meta {
            component.licenses = convert_licenses(&meta);
            component.description = meta.description.map(|s| NormalizedString::new(&s));
            if let Some(identifiers) = meta.identifiers {
                if let Some(cpe) = identifiers.cpe {
                    component.cpe = Some(Cpe::new(&cpe));
                } else if let Some(possible_cpes) = identifiers.possible_cpes {
                    component.evidence = cpes_to_evidence(&possible_cpes);
                }
            }
            if let Some(homepage) = meta.homepage {
                external_references.push(convert_homepage(&homepage));
                // The homepage of a package also tells who created it. A component only has a
                // field for that from CycloneDX v1.6 on, so it is passed along in a property
                // that is turned into the manufacturer after the SBOM is converted.
                properties.push(Property::new("bombon:manufacturer-url", &homepage));
            }
        }
        component.properties = Some(Properties(properties));

        if !external_references.is_empty() {
            component.external_references = Some(ExternalReferences(external_references));
        }

        if !derivation.patches.is_empty() {
            component.pedigree = Some(Pedigree {
                ancestors: None,
                descendants: None,
                variants: None,
                commits: None,
                patches: Some(convert_patches(
                    &derivation.patches,
                    // The patches named by a build recipe are not necessarily available. They
                    // are listed nonetheless.
                    matches!(
                        derivation.identification,
                        Identification::Recipe | Identification::RecipeWithSameSource
                    ),
                )),
                notes: None,
            });
        }

        Self(component)
    }
}

impl From<CycloneDXComponent> for Component {
    fn from(value: CycloneDXComponent) -> Self {
        value.0
    }
}

fn string_to_url(s: &str) -> external_reference::Uri {
    external_reference::Uri::Url(Uri::new(s))
}

/// Convert licenses from a derivations meta field.
///
/// Converts a list of licenses to a list of licenses in the ``CycloneDX`` format.
///
/// Converts a single license to a SPDX expression to be able to accommodate the new compound
/// license types.
///
/// Assumes that compound licenses are never inside a list.
fn convert_licenses(meta: &Meta) -> Option<Licenses> {
    Some(Licenses(match &meta.license {
        Some(license) => match license {
            derivation::LicenseField::LicenseList(list) => {
                list.0.clone().into_iter().map(convert_license).collect()
            }
            derivation::LicenseField::LicenseExpression(expr) => {
                vec![LicenseChoice::Expression(SpdxExpression::new(&expr.0))]
            }
            derivation::LicenseField::String(_) => return None,
        },
        _ => return None,
    }))
}

fn convert_license(license: derivation::License) -> LicenseChoice {
    match license.spdx_id {
        Some(spdx_id) => LicenseChoice::License(License::license_id(&spdx_id)),
        None => LicenseChoice::License(License::named_license(&license.full_name)),
    }
}

fn cpes_to_evidence(possible_cpes: &[derivation::Cpe]) -> Option<ComponentEvidence> {
    if possible_cpes.is_empty() {
        return None;
    }
    let methods = Methods(
        possible_cpes
            .iter()
            .map(|cpe| Method {
                // Because we extract this information from the package definition.
                // See https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf p.63
                technique: "manifest-analysis".to_string(),
                // Safety: division could panic here but we've already prevented len() from being 0 above.
                #[allow(clippy::cast_precision_loss)]
                confidence: ConfidenceScore::new(1.0 / possible_cpes.len() as f32),
                value: cpe.cpe.clone(),
            })
            .collect(),
    );
    // ComponentEvidence and Identity do not have Default implementations.
    Some(ComponentEvidence {
        identity: Some(Identity {
            field: IdentityField::Cpe,
            methods: Some(methods),
            confidence: None,
            tools: None,
        }),
        licenses: None,
        copyright: None,
        occurrences: None,
        callstack: None,
    })
}

/// Where the facts about a component come from.
fn origin(identification: Identification, is_file: bool) -> &'static str {
    match identification {
        _ if is_file => "file",
        Identification::Package => "package",
        Identification::Recipe => "recipe",
        Identification::RecipeWithSameSource => "recipe+same-source-package",
        Identification::Name => "name",
    }
}

/// Record that the version of a component was split off a name.
fn name_to_evidence(name: &str, version: &str) -> ComponentEvidence {
    ComponentEvidence {
        identity: Some(Identity {
            field: IdentityField::Version,
            methods: Some(Methods(vec![Method {
                technique: "filename".to_string(),
                // This marks the version as derived from a name. It is not a measurement.
                confidence: ConfidenceScore::new(0.5),
                value: Some(format!("{name}-{version}")),
            }])),
            confidence: None,
            tools: None,
        }),
        licenses: None,
        copyright: None,
        occurrences: None,
        callstack: None,
    }
}

fn convert_distribution(url: &str) -> ExternalReference {
    ExternalReference {
        external_reference_type: ExternalReferenceType::Distribution,
        url: string_to_url(url),
        comment: None,
        hashes: None,
    }
}

fn convert_src(src: &Src) -> Vec<ExternalReference> {
    assert!(
        !src.urls.is_empty(),
        "src.urls must contain at least one value to generate ExternalReference",
    );
    assert!(
        !src.urls.iter().any(String::is_empty),
        "All urls in src.urls must not be empty strings to generate ExternalReference",
    );
    src.urls
        .iter()
        .map(|u| ExternalReference {
            external_reference_type: ExternalReferenceType::Vcs,
            url: string_to_url(u),
            comment: None,
            hashes: src.hash.clone().and_then(|s| convert_hash(&s)),
        })
        .collect()
}

impl From<hash::Algorithm> for HashAlgorithm {
    fn from(value: hash::Algorithm) -> Self {
        match value {
            hash::Algorithm::Md5 => HashAlgorithm::MD5,
            hash::Algorithm::Sha1 => HashAlgorithm::SHA1,
            hash::Algorithm::Sha256 => HashAlgorithm::SHA_256,
            hash::Algorithm::Sha512 => HashAlgorithm::SHA_512,
        }
    }
}

fn convert_hash(s: &str) -> Option<Hashes> {
    // If it's not an SRI hash, we'll return None
    let sri_hash = SriHash::from_str(s).ok()?;
    let hash = Hash {
        content: HashValue(sri_hash.hex_digest()),
        alg: sri_hash.algorithm.into(),
    };
    Some(Hashes(vec![hash]))
}

fn convert_homepage(homepage: &str) -> ExternalReference {
    ExternalReference {
        external_reference_type: ExternalReferenceType::Website,
        url: string_to_url(homepage),
        comment: None,
        hashes: None,
    }
}

fn metadata_from_derivation(derivation: Derivation) -> Metadata {
    Metadata {
        timestamp: None,
        tools: Some(metadata_tools()),
        authors: None,
        component: Some(CycloneDXComponent::from_derivation(derivation).into()),
        manufacture: None,
        supplier: None,
        licenses: None,
        properties: None,
        lifecycles: None,
    }
}

fn metadata_tools() -> Tools {
    let mut component = Component::new(Classification::Application, "bombon", VERSION, None);
    component.external_references = Some(ExternalReferences(vec![convert_homepage(
        "https://github.com/nikstur/bombon",
    )]));
    component.description = Some(NormalizedString::new(
        "Nix CycloneDX Software Bills of Materials (SBOMs)",
    ));
    component.licenses = Some(Licenses(vec![LicenseChoice::License(License::license_id(
        "MIT",
    ))]));

    Tools::Object {
        services: None,
        components: Some(Components(vec![component])),
    }
}

/// Convert patches to the `CycloneDX` format.
///
/// A patch that cannot be read is either left out or, if `keep_unavailable` is set, listed
/// with a reference to the file instead of its content.
fn convert_patches(patches: &[String], keep_unavailable: bool) -> Patches {
    let cyclonedx_patches = patches
        .iter()
        .filter_map(|patch| {
            let diff = match fs::read_to_string(patch) {
                Ok(content) => Diff {
                    text: Some(AttachedText {
                        content_type: Some(NormalizedString::new("text/plain")),
                        encoding: None,
                        content,
                    }),
                    url: None,
                },
                Err(_) if keep_unavailable => Diff {
                    text: None,
                    url: Some(Uri::new(patch)),
                },
                Err(_) => return None,
            };
            Some(Patch {
                // As we know nothing about the patch at this level, the safest is to assume that
                // it's unofficial
                patch_type: PatchClassification::Unofficial,
                diff: Some(diff),
                resolves: None,
            })
        })
        .collect::<Vec<_>>();
    Patches(cyclonedx_patches)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    const SHA256: &str = "sha256-PToblzryGBFPT4ibuqL0wDfequDI6BXuw4HD1Ua5dKA=";

    /// Serialize a single derivation as a component.
    fn component(derivation: Derivation) -> Result<Value> {
        let bom = CycloneDXBom(Bom {
            components: Some(CycloneDXComponents::from_derivations([derivation]).into()),
            ..Bom::default()
        });
        let json: Value = serde_json::from_slice(&bom.serialize()?)?;
        Ok(json["components"][0].clone())
    }

    fn package() -> Derivation {
        Derivation {
            path: "/nix/store/b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev".into(),
            name: Some("libssh2-1.11.1".into()),
            pname: Some("libssh2".into()),
            version: Some("1.11.1".into()),
            output_name: Some("dev".into()),
            identification: Identification::Recipe,
            ..Derivation::default()
        }
    }

    fn file(hash: Option<&str>) -> Derivation {
        Derivation {
            path: "/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz".into(),
            name: Some("xz-5.8.3.tar.gz".into()),
            src: Some(Src {
                urls: vec!["https://tukaani.org/xz/xz-5.8.3.tar.gz".into()],
                hash: hash.map(Into::into),
            }),
            is_file: true,
            identification: Identification::Recipe,
            ..Derivation::default()
        }
    }

    #[test]
    fn origins() -> Result<()> {
        let origin = |derivation: Derivation| -> Result<Value> {
            Ok(component(derivation)?["properties"].clone())
        };
        let expected =
            |value: &str| serde_json::json!([{ "name": "bombon:origin", "value": value }]);

        assert_eq!(
            origin(Derivation {
                identification: Identification::Package,
                ..package()
            })?,
            expected("package")
        );
        assert_eq!(origin(package())?, expected("recipe"));
        assert_eq!(
            origin(Derivation {
                identification: Identification::RecipeWithSameSource,
                ..package()
            })?,
            expected("recipe+same-source-package")
        );
        assert_eq!(
            origin(Derivation {
                identification: Identification::Name,
                ..package()
            })?,
            expected("name")
        );
        assert_eq!(origin(file(None))?, expected("file"));
        Ok(())
    }

    #[test]
    fn creator() -> Result<()> {
        let meta = |homepage: Option<&str>| -> Result<Meta> {
            Ok(serde_json::from_value(serde_json::json!({
                "description": "A library",
                "homepage": homepage,
            }))?)
        };
        let url = |component: &Value| -> Vec<Value> {
            component["properties"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|property| property["name"] == "bombon:manufacturer-url")
                .map(|property| property["value"].clone())
                .collect()
        };

        // A package and a recipe with the metadata of a same-source package name their homepage.
        for identification in [
            Identification::Package,
            Identification::RecipeWithSameSource,
        ] {
            let component = component(Derivation {
                meta: Some(meta(Some("https://libssh2.org"))?),
                identification,
                ..package()
            })?;
            assert_eq!(url(&component), ["https://libssh2.org"]);
            // The homepage is still referred to as the website.
            assert_eq!(component["externalReferences"][0]["type"], "website");
            assert_eq!(
                component["externalReferences"][0]["url"],
                "https://libssh2.org"
            );
            assert_eq!(component["properties"][0]["name"], "bombon:origin");
        }

        // Nothing is made up for packages without a homepage and for recipes.
        let without_homepage = component(Derivation {
            meta: Some(meta(None)?),
            identification: Identification::Package,
            ..package()
        })?;
        assert!(url(&without_homepage).is_empty());
        assert!(url(&component(package())?).is_empty());
        assert!(url(&component(file(None))?).is_empty());
        Ok(())
    }

    #[test]
    fn vendored_components_have_no_origin() -> Result<()> {
        let directory = std::env::temp_dir().join(format!(
            "bombon-transformer-test-vendored-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory)?;
        fs::write(
            directory.join("serde.cdx.json"),
            r#"{
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "components": [
                    { "type": "library", "name": "serde", "version": "1.0.219", "bom-ref": "pkg:cargo/serde@1.0.219" }
                ]
            }"#,
        )?;
        let mut components = CycloneDXComponents::from_derivations([package()]);
        let extended = components.extend_from_directory(&directory, &package().path);
        fs::remove_dir_all(&directory)?;
        extended?;

        let bom = CycloneDXBom(Bom {
            components: Some(components.into()),
            ..Bom::default()
        });
        let json: Value = serde_json::from_slice(&bom.serialize()?)?;
        let components = json["components"]
            .as_array()
            .context("Missing components")?;
        assert_eq!(components.len(), 2);
        for component in components {
            assert_eq!(
                component.get("properties").is_some(),
                component["name"] == "libssh2"
            );
        }
        Ok(())
    }

    #[test]
    fn package_from_recipe() -> Result<()> {
        let component = component(Derivation {
            src: Some(Src {
                urls: vec!["https://example.org/libssh2-1.11.1.tar.gz".into()],
                hash: Some(SHA256.into()),
            }),
            ..package()
        })?;

        assert_eq!(component["type"], "application");
        assert_eq!(component["name"], "libssh2");
        assert_eq!(component["version"], "1.11.1");
        assert_eq!(component["purl"], "pkg:nix/libssh2@1.11.1");
        assert_eq!(
            component["bom-ref"],
            "b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev"
        );
        assert_eq!(component["externalReferences"][0]["type"], "vcs");
        assert_eq!(
            component["externalReferences"][0]["url"],
            "https://example.org/libssh2-1.11.1.tar.gz"
        );
        assert_eq!(
            component["externalReferences"][0]["hashes"][0]["content"],
            "3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0"
        );
        // Name and version are stated by the recipe, so there is nothing to mark.
        assert!(component.get("evidence").is_none());
        Ok(())
    }

    #[test]
    fn downloaded_file() -> Result<()> {
        let component = component(file(Some(SHA256)))?;

        assert_eq!(component["type"], "file");
        assert_eq!(component["name"], "xz-5.8.3.tar.gz");
        assert!(component.get("version").is_none());
        assert!(component.get("purl").is_none());
        assert_eq!(component["hashes"][0]["alg"], "SHA-256");
        assert_eq!(
            component["hashes"][0]["content"],
            "3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0"
        );
        assert_eq!(component["externalReferences"][0]["type"], "distribution");
        assert_eq!(
            component["externalReferences"][0]["url"],
            "https://tukaani.org/xz/xz-5.8.3.tar.gz"
        );
        assert!(component["externalReferences"][0].get("hashes").is_none());
        Ok(())
    }

    #[test]
    fn downloaded_file_tree() -> Result<()> {
        let component = component(file(None))?;

        assert_eq!(component["type"], "file");
        assert!(component.get("hashes").is_none());
        assert_eq!(component["externalReferences"][0]["type"], "distribution");
        Ok(())
    }

    #[test]
    fn version_from_name() -> Result<()> {
        let component = component(Derivation {
            path: "/nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-emacs-pgtk-with-packages-31.1"
                .into(),
            name: Some("emacs-pgtk-with-packages".into()),
            version: Some("31.1".into()),
            identification: Identification::Name,
            ..Derivation::default()
        })?;

        assert_eq!(component["name"], "emacs-pgtk-with-packages");
        assert_eq!(component["version"], "31.1");
        let identity = &component["evidence"]["identity"];
        assert_eq!(identity["field"], "version");
        assert_eq!(identity["methods"][0]["technique"], "filename");
        assert_eq!(
            identity["methods"][0]["value"],
            "emacs-pgtk-with-packages-31.1"
        );
        Ok(())
    }

    #[test]
    fn patches_from_recipe() -> Result<()> {
        let available = std::env::temp_dir().join(format!(
            "bombon-transformer-test-{}.patch",
            std::process::id()
        ));
        fs::write(&available, "--- a\n+++ b\n")?;
        let unavailable = "/nix/store/00000000000000000000000000000000-CVE-2026-7598.patch";
        let patches = vec![
            available.to_string_lossy().into_owned(),
            unavailable.to_string(),
        ];

        let from_recipe = component(Derivation {
            patches: patches.clone(),
            ..package()
        });
        let from_package = component(Derivation {
            patches,
            identification: Identification::Package,
            ..package()
        });
        fs::remove_file(&available)?;

        // Patches named by a recipe are all listed, with their content if it is available.
        let from_recipe = from_recipe?;
        let listed = from_recipe["pedigree"]["patches"]
            .as_array()
            .context("Missing patches")?;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["diff"]["text"]["content"], "--- a\n+++ b\n");
        assert!(listed[1]["diff"].get("text").is_none());
        assert_eq!(listed[1]["diff"]["url"], unavailable);

        // Patches of a package object are part of the build and thus expected to be available.
        let from_package = from_package?;
        let listed = from_package["pedigree"]["patches"]
            .as_array()
            .context("Missing patches")?;
        assert_eq!(listed.len(), 1);
        Ok(())
    }

    #[test]
    fn serial_number_from_seed() {
        let a = "/nix/store/bqwmxjkrkmn1kqivq4pr053j68biq4k4-hello-2.12.1.cdx.json";
        let b = "/nix/store/lcxn67gbjdcr6bjf1rcs03ywa7gcslr2-git-2.47.0.cdx.json";

        assert_eq!(
            derive_serial_number(a.as_bytes()),
            derive_serial_number(a.as_bytes())
        );
        assert_ne!(
            derive_serial_number(a.as_bytes()),
            derive_serial_number(b.as_bytes())
        );
    }

    fn derivation(path: &str) -> Derivation {
        Derivation {
            path: path.to_string(),
            pname: Some("openssl".to_string()),
            version: Some("3.6.4".to_string()),
            ..Derivation::default()
        }
    }

    fn vendored(bom_ref: &str) -> Component {
        let mut component = Component::new(
            Classification::Library,
            "serde",
            "1.0.219",
            Some(bom_ref.to_string()),
        );
        component.purl = Purl::new("cargo", "serde", "1.0.219").ok();
        component
    }

    #[test]
    fn deduplicate() {
        let out = "/nix/store/3xcc0ljbmnp1nlk0pnjiqrbqzm7m3ag0-openssl-3.6.4";
        let bin = "/nix/store/44gxi8liiqmd6fbnr2b7bbxl0dkfb52m-openssl-3.6.4-bin";
        let mut components =
            CycloneDXComponents::from_derivations([derivation(out), derivation(bin)]);
        components.0.0.extend([
            vendored("registry+https://github.com/rust-lang/crates.io-index#serde@1.0.219"),
            vendored("pkg:cargo/serde@1.0.219"),
        ]);

        components.deduplicate();

        // The outputs of a derivation share a PURL but are different components.
        assert!(components.bom_refs().contains(&bom_ref(out)));
        assert!(components.bom_refs().contains(&bom_ref(bin)));
        // Vendored components with the same PURL are the same component.
        assert_eq!(components.0.0.len(), 3);
    }
}
