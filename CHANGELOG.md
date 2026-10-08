# Changelog

## Unreleased

### Added

- The components of the Go modules that `passthruVendoredSbom.go` adds now have
  evidence of their licenses. The licenses are detected from their texts in the
  sources of the modules, so they are included as evidence and not as the
  licenses of the components. If the package is built with `proxyVendor`, they
  are detected by `cyclonedx-gomod`, otherwise by `askalono` from the license
  files in the `vendor` directory.
- The SBOM now states how complete the dependencies of every component are, as
  `compositions`. BSI TR-03183-2 requires this. They are stated as `unknown`, as
  what a component contains without referring to it is not known, and as
  `incomplete` for a component that depends on something that was removed with
  `excludes`. They are never stated as `complete`.
- Added `passthruVendoredSbom.npm` to generate SBOMs for vendored npm
  dependencies of packages that use `npmConfigHook` (e.g. anything built with
  `buildNpmPackage`). The SBOM is generated with `npm sbom`.
- Added `passthruVendoredSbom.pnpm` to generate SBOMs for vendored pnpm
  dependencies of packages that use `pnpmConfigHook`. The SBOM is generated
  with `pnpm sbom`, which requires pnpm 11 or newer.
- Added `passthruVendoredSbom.go` to generate SBOMs for vendored Go
  dependencies of packages built with `buildGoModule`. The SBOM is generated
  with `cyclonedx-gomod`.
- Added emitting a CycloneDX dependency graph spanning runtime dependencies,
  vendored language-level SBOMs' graphs, and optionally build-time dependencies
  via the `includeBuildtimeDependencies` flag.
- Added support for compound licenses from Nixpkgs. Compound licenses are now
  included as SPDX expressions in the SBOM.
- Added support for CycloneDX v1.7.
- Files that are downloaded without stating a package name and version (e.g.
  with a plain `fetchurl`) and end up in the runtime closure are now included
  as components of type `file`. They carry the URL they are downloaded from
  and, for single files, their hash. They have neither a version nor a PURL.

- Added the `metadataFrom` option to `buildBom`. The packages given this way
  are followed to find the metadata (license, description, CPE, etc.) of
  dependencies but, unlike `extraPaths`, are not added to the SBOM, not even
  as buildtime dependencies, and their vendored SBOMs are not read.
- Added the `packageSets` option to `buildBom`. Dependencies whose package is
  not found by following attributes are looked up in these package sets by the
  name of their build recipe, also without the prefix that the package set of
  a language adds (e.g. `python3.13-`). A package is only used if it is built
  by exactly that recipe.
- Added the `inferFromSameSource` option to `buildBom`. If a dependency is not
  found in `packageSets` but a package of the same name is built from the same
  source, the license, description, homepage and identifiers of that package
  are used. Enabled by default.
- Added the creator of a component as required by BSI TR-03183-2: the
  homepage of its package is included as the `manufacturer` of the component.
  This is the upstream project, also for packages that are patched. Components
  whose package is not known or has no homepage have no `manufacturer`.
- Added the `timestamp`, `creator` and `subject` options to `buildBom` to tell
  when the data of the SBOM was compiled, who created it, and the name, the
  version and the creator of what it describes, as required by BSI TR-03183-2.
  Without them the SBOM is the same as before. bombon never uses the current
  time, so the same input still yields the same SBOM.
- Added the property `bombon:origin` to every component of a dependency. It
  tells whether the component is described by a package, a build recipe, a
  build recipe with the metadata of a same-source package, a download or a
  name.

### Changed

- The packages a SBOM is generated for are not built anymore just to generate
  the SBOM. Only the runtime closure, the patches and the vendored SBOMs are.
- Dependencies that are only referred to in a string (e.g. `"${pkgs.jq}/bin/jq"`)
  are now described by what their build recipe (`.drv` file) states instead of
  by what can be guessed from their store path. Their name, version, patches
  and source URL are taken from the recipe. Dependencies that were dropped
  before because no version could be guessed (e.g. outputs like `-lib` or
  `-dev`) are now included, and versions that contain dashes (e.g.
  `1.0.22-unstable-2026-08-13`) are now correct. Expect SBOMs of targets with
  such dependencies, most notably NixOS systems, to contain more components.
- Splitting a version off a name is now only done if the build recipe states
  nothing but a name. Such components are marked with identity evidence
  (technique `filename`).

### Fixed

- A pattern in `excludes` can now have characters that are special to the
  shell, like `(`, `|`, `*` or a space, and can begin with a dash. The build of
  the SBOM failed for such patterns as they were not quoted.
- The dependency graph is connected to what the SBOM describes now. A
  dependency was only included if both sides are components, so everything a
  derivation refers to through a store path that is not a component (e.g. the
  unit files and the configuration of a NixOS system) was not connected to it.
  Such a store path is now followed to the components it refers to in turn.
  This changes what a dependency means: a component depends on another one
  directly or through store paths that are not part of the SBOM. Buildtime
  dependencies are not affected.
- What the SBOM describes now depends on the `extraPaths`.
- Components that describe a derivation are not deduplicated by their PURL
  anymore. The PURL only consists of the name and the version, so all but one
  output of a derivation with multiple outputs (e.g. `out`, `bin` and `dev`)
  were removed from the SBOM, together with the dependencies on them.
  Components from vendored SBOMs are still deduplicated by their PURL.

## 0.4.0

### Added

- Added the ability to extract patches from a derivation and include them in
  the SBOM.
- Added the ability to include multiple source URLs as external references.
- Added the ability to extract CPEs from Nix packages. "Guessed" CPEs in
  the `possibleCPEs` field are included as evidence in the SBOM.
- Added deduplication of components based on PURL. Only the first component
  with a certain PURL will be kept in the final SBOM.

### Changed

- Derivations without a version are now excluded from the final SBOM as these
  are usually ad-hoc created (e.g. for systemd units, etc.) and thus not
  relevant.
- Improved the guessing of versions from a store path. Now the last component
  is usually picked up as the version of the package.

### Fixed

- Fixed an issue where some components would receive an empty string as VCS
  external reference.

## 0.3.0

### Added

- Added the ability to collect SBOMs from vendored dependencies (e.g. from Rust
  or Go dependencies).
- Added the option `excludes` to `buildBom` to exclude store paths via regex
  patterns from the final SBOM.
- Added the option `extraPaths` to `buildBom` to consider extra dependencies
  but still generating an SBOM for the original derivation.
- Hashes of fixed output derivations are now included in the SBOM.
- A derivation's `src` url and hash are now included in the SBOM.
- Derivations' descriptions are now included in the SBOM.

### Changed

- `doc` and `man` outputs are not included in the SBOM anymore.
- Generate CycloneDX v1.5 SBOMs instead of v1.4.
- The created SBOMS are now reproducible because they derive their serial
  number from a known input instead of randomly generating it.

### Fixed

- Fixed cross-compilation for SBOMs.
