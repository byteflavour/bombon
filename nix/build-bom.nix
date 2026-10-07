{
  lib,
  runCommand,
  transformer,
  cyclonedx-cli,
  buildtimeDependencies,
  runtimeDependencies,
  recipeClosure,
  recipes,
}:

drv:
{
  extraPaths ? [ ],
  metadataFrom ? [ ],
  packageSets ? [ ],
  inferFromSameSource ? true,
  includeBuildtimeDependencies ? false,
  excludes ? [ ],
}:

let
  # The build recipes are read once: they describe the dependencies and are looked up in the
  # package sets.
  buildRecipes = recipeClosure drv extraPaths;

  buildtime = buildtimeDependencies drv extraPaths {
    inherit metadataFrom packageSets inferFromSameSource;
    recipeClosure = buildRecipes;
  };

  args =
    lib.optionals includeBuildtimeDependencies [
      "--include-buildtime-dependencies"
    ]
    ++ lib.optionals (excludes != [ ]) (lib.map (e: "--exclude ${e}") excludes);
in
runCommand "${drv.name}.cdx.json"
  {
    nativeBuildInputs = [
      transformer
      cyclonedx-cli
    ];
  }
  ''
    bombon-transformer ${drv} \
      ${toString args} \
      --serial-number-seed "$out" \
      --recipes ${recipes drv buildRecipes} \
      --same-source-metadata ${buildtime.sameSourceMetadata} \
      ${buildtime.packages} \
      ${runtimeDependencies drv extraPaths} \
      tmp.cdx.json

    cyclonedx convert \
      --input-format=json \
      --input-file=tmp.cdx.json \
      --output-version=v1_7 \
      --output-file=$out
  ''
