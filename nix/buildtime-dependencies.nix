{
  lib,
  writeText,
  runCommand,
  jq,
}:

let

  # Find the outputs of a derivation.
  #
  # Returns a list of all derivations that correspond to an output of the input
  # derivation.
  drvOutputs =
    drv: if builtins.hasAttr "outputs" drv then map (output: drv.${output}) drv.outputs else [ drv ];

  # Find the dependencies of a derivation via it's `drvAttrs`.
  #
  # Returns a list of all dependencies.
  drvDeps =
    drv:
    lib.mapAttrsToList (
      _k: v:
      if lib.isDerivation v then
        (drvOutputs v)
      else if lib.isList v then
        lib.concatMap drvOutputs (lib.filter lib.isDerivation v)
      else
        [ ]
    ) drv.drvAttrs;

  wrap = drv: {
    # The context is discarded so that the key can be used as an attribute name.
    key = builtins.unsafeDiscardStringContext drv.outPath;
    inherit drv;
  };

  # Walk through the whole DAG of dependencies, using the `outPath` as an
  # index for the elements.
  #
  # Returns a list of all of `drv`'s buildtime dependencies that are not in
  # `known`, an attrset of store paths. Dependencies that are known are not
  # followed, since their dependencies are known as well.
  # Elements in the list have two fields:
  #
  #  - key: the store path of the input.
  #  - drv: the actual derivation object.
  #
  # All outputs are included because they have different outPaths
  buildtimeDerivations =
    drvs: known:
    lib.filter (item: !(known ? ${item.key})) (
      builtins.genericClosure {
        startSet = map wrap (lib.concatMap drvOutputs drvs);
        operator = item: if known ? ${item.key} then [ ] else map wrap (lib.concatLists (drvDeps item.drv));
      }
    );

  # Like lib.getAttrs but omit attrs that do not exist.
  optionalGetAttrs =
    names: attrs: lib.genAttrs (builtins.filter (x: lib.hasAttr x attrs) names) (name: attrs.${name});

  # The meta attributes of a derivation with its license normalised to SPDX.
  normalisedMeta =
    drv:
    let
      # A license that is a hand-rolled attrset or a plain string does not carry `licenseType`, so
      # `lib.licenses.toSPDX` throws `attribute 'licenseType' missing` and aborts the entire SBOM.
      # Such a license can also be part of a compound license, which is why the conversion is
      # done here.
      bracket =
        license:
        if
          lib.elem (license.licenseType or null) [
            "compound"
            "exception"
          ]
        then
          "(${toSPDX license})"
        else
          toSPDX license;
      toSPDX =
        license:
        if lib.isString license then
          license
        else if !(license ? licenseType) then
          "LicenseRef-unknown"
        else if license.licenseType == "simple" then
          license.spdxId or "LicenseRef-nixos-${license.shortName}"
        else if license.licenseType == "compound" then
          lib.concatMapStringsSep " ${license.operator} " bracket license.licenses
        else if license.licenseType == "exception" then
          "${bracket license.license} ${license.operator} ${bracket license.exception}"
        else if license.licenseType == "plus" then
          "${bracket license.license}${license.operator}"
        else
          "LicenseRef-unknown";
    in
    lib.recursiveUpdate drv.meta (
      lib.optionalAttrs (drv.meta ? license) {
        license = if !(lib.isList drv.meta.license) then toSPDX drv.meta.license else drv.meta.license;
      }
    );

  # The files of the patches of a derivation.
  #
  # Usually the patches are a list of files but some derivations group them, e.g. in an attrset.
  patchFiles =
    patches:
    if lib.isList patches then
      lib.concatMap patchFiles patches
    else if lib.isStringLike patches then
      [ patches ]
    else if lib.isAttrs patches then
      lib.concatMap patchFiles (lib.attrValues patches)
    else
      [ ];

  # Retrieve only the required fields from a derivation.
  #
  # Also renames outPath so that builtins.toJSON actually emits JSON and not
  # only the nix store path.
  #
  # A derivation that is only known to describe a dependency (`metadataOnly`) is not part of the
  # build closure. It contributes nothing but its description: no build-time dependencies and no
  # vendored SBOM, which would have to be built.
  fields =
    metadataOnly: drv:
    (optionalGetAttrs [
      "name"
      "pname"
      "version"
      "outputName"
      "outputHash"
    ] drv)
    // {
      # The store paths are only used to identify the derivations. Their string context is
      # discarded so that the derivations do not have to be built to generate the SBOM.
      path = builtins.unsafeDiscardStringContext drv.outPath;
      patches = patchFiles (drv.patches or [ ]);
    }
    // lib.optionalAttrs metadataOnly {
      inherit metadataOnly;
    }
    // lib.optionalAttrs (!metadataOnly) {
      # The store paths of this derivation's direct build-time dependencies, so the transformer can emit build-time `dependsOn` edges.
      buildReferences = lib.unique (
        map (o: builtins.unsafeDiscardStringContext o.outPath) (lib.concatLists (drvDeps drv))
      );
    }
    // lib.optionalAttrs (drv ? src && drv.src ? urls) {
      src = {
        inherit (drv.src) urls;
      }
      // lib.optionalAttrs (drv.src ? outputHash) {
        hash = drv.src.outputHash;
      };
    }
    // lib.optionalAttrs (!metadataOnly && drv ? bombonVendoredSbom) {
      vendoredSbom = drv.bombonVendoredSbom.outPath;
    }
    // lib.optionalAttrs (drv ? meta) {
      meta = normalisedMeta drv;
    };

  # The names a package can be found under in a package set, from the file name of its recipe.
  #
  # The package set of a language prefixes the names of its packages with the name of the
  # language or interpreter (e.g. `python3.13-requests`, `perl5.42.0-URI` or `r-ggplot2`), so the
  # name is also tried without its first part. Perl modules additionally lose their dashes
  # (`perl5.42.0-Module-Build` is `ModuleBuild`).
  candidateNames =
    recipe:
    let
      name =
        (builtins.parseDrvName (lib.removeSuffix ".drv" (builtins.substring 33 (-1) (baseNameOf recipe))))
        .name;
      parts = lib.splitString "-" name;
      rest = lib.tail parts;
    in
    lib.unique (
      [ name ]
      ++ lib.optionals (lib.length parts > 1) [
        (lib.concatStringsSep "-" rest)
        (lib.concatStrings rest)
      ]
    );

  recipeOf = drv: builtins.unsafeDiscardStringContext drv.drvPath;

  # The packages that are found in the package sets under the names of a recipe.
  #
  # Looking up a package can fail, e.g. because it is marked as insecure. Such packages are
  # skipped.
  candidates =
    packageSets: recipe:
    lib.concatMap (
      set:
      lib.concatMap (
        name:
        let
          candidate = builtins.tryEval (
            let
              drv = set.${name};
              recipe = recipeOf drv;
            in
            # The recipe is forced here because that is what fails for such packages.
            if lib.isDerivation drv then
              builtins.seq recipe {
                inherit drv recipe;
              }
            else
              null
          );
        in
        lib.optional (set ? ${name} && candidate.success && candidate.value != null) candidate.value
      ) (candidateNames recipe)
    ) packageSets;

  # Whether a package is built from a source that the recipe is built from as well.
  hasSameSource =
    recipe: drv:
    let
      result = builtins.tryEval (
        drv ? src && lib.isDerivation drv.src && lib.elem (recipeOf drv.src) recipe.inputRecipes
      );
    in
    result.success && result.value;

in

# This returns two JSON files:
#
#  - packages: what is known about the packages that are found by following the attributes of
#    drv, extraPaths and metadataFrom, and by looking up the build recipes of drv in packageSets.
#  - sameSourceMetadata: the metadata of packages in packageSets that are not built by one of the
#    build recipes of drv but from the same source as one of them, by the store path of that
#    recipe.
#
# recipeClosure is the list of build recipes of drv and extraPaths, as returned by
# `recipe-closure.nix`.
drv: extraPaths:
{
  recipeClosure,
  metadataFrom ? [ ],
  packageSets ? [ ],
  inferFromSameSource ? true,
}:

let

  # Only read the build recipes if there is something to look them up in.
  lookups =
    if packageSets == [ ] then
      [ ]
    else
      map (recipe: {
        inherit recipe;
        candidates = candidates packageSets recipe.key;
      }) recipeClosure;

  # The packages that are built by exactly one of the build recipes.
  found = lib.concatMap (
    lookup: map (c: c.drv) (lib.filter (c: c.recipe == lookup.recipe.key) lookup.candidates)
  ) lookups;

  # The build closure of the SBOM's subject.
  closure = buildtimeDerivations ([ drv ] ++ extraPaths) { };

  # The packages that only describe dependencies, with what they depend on in turn. What is part
  # of the build closure is left out so that it is described once.
  metadataClosure = buildtimeDerivations (metadataFrom ++ found) (
    lib.genAttrs (map (item: item.key) closure) (_: true)
  );

  allBuildtimeDerivations = closure ++ metadataClosure;

  knownRecipes = lib.genAttrs (map (item: recipeOf item.drv) allBuildtimeDerivations) (_: true);

  sameSource = lib.listToAttrs (
    lib.concatMap (
      lookup:
      let
        packages = lib.filter (c: hasSameSource lookup.recipe c.drv && c.drv ? meta) lookup.candidates;
      in
      lib.optional (!(knownRecipes ? ${lookup.recipe.key}) && packages != [ ]) (
        lib.nameValuePair lookup.recipe.key { meta = normalisedMeta (lib.head packages).drv; }
      )
    ) (lib.optionals inferFromSameSource lookups)
  );

  unformattedJson = writeText "${drv.name}-unformatted-buildtime-dependencies.json" (
    builtins.toJSON (
      map (item: fields false item.drv) closure ++ map (item: fields true item.drv) metadataClosure
    )
  );

in

{
  # Format the json so that the transformer can better report where errors occur
  packages = runCommand "${drv.name}-buildtime-dependencies.json" { } ''
    ${jq}/bin/jq < ${unformattedJson} > "$out"
  '';

  sameSourceMetadata = writeText "${drv.name}-same-source-metadata.json" (builtins.toJSON sameSource);
}
