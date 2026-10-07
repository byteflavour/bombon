{
  lib,
  runCommand,
  transformer,
  cyclonedx-cli,
  jq,
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
  timestamp ? null,
  creator ? null,
  subject ? null,
  includeBuildtimeDependencies ? false,
  excludes ? [ ],
}:

let
  fail = option: message: throw "bombon: ${option}: ${message}";

  isNonEmptyString = value: lib.isString value && value != "";

  # Check that only the allowed attributes are given and that all of them are non-empty strings.
  checkStrings =
    option: allowed: value:
    let
      unknown = lib.attrNames (removeAttrs value allowed);
      invalid = lib.attrNames (lib.filterAttrs (_: v: !isNonEmptyString v) value);
    in
    if !lib.isAttrs value then
      fail option "has to be an attribute set"
    else if unknown != [ ] then
      fail option "unknown attribute ${lib.concatStringsSep ", " unknown}"
    else if invalid != [ ] then
      fail option "${lib.concatStringsSep ", " invalid} has to be a non-empty string"
    else
      value;

  # Who created something: an email address or a URL, and optionally a name.
  checkCreator =
    option: value:
    let
      checked = checkStrings option [ "name" "email" "url" ] value;
    in
    if checked ? email || checked ? url then checked else fail option "needs an email or a url";

  checkedTimestamp =
    if
      lib.isString timestamp
      && builtins.match "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z" timestamp != null
    then
      timestamp
    else
      fail "timestamp" "has to be a date and time in UTC like 2026-01-31T12:00:00Z";

  checkedSubject =
    if !lib.isAttrs subject then
      fail "subject" "has to be an attribute set"
    else
      checkStrings "subject" [ "name" "version" ] (removeAttrs subject [ "creator" ])
      // lib.optionalAttrs (subject ? creator) {
        creator = checkCreator "subject.creator" subject.creator;
      };

  # What is said about the SBOM and its subject. Their name and version are passed to the
  # transformer because the PURL is made of them. The rest is added to the final SBOM.
  finishOptions =
    lib.optionalAttrs (timestamp != null) { timestamp = checkedTimestamp; }
    // lib.optionalAttrs (creator != null) { creator = checkCreator "creator" creator; }
    // lib.optionalAttrs (subject != null && checkedSubject ? creator) {
      subject.creator = checkedSubject.creator;
    };

  subjectArgs = lib.optionals (subject != null) (
    lib.optionals (checkedSubject ? name) [
      "--subject-name"
      (lib.escapeShellArg checkedSubject.name)
    ]
    ++ lib.optionals (checkedSubject ? version) [
      "--subject-version"
      (lib.escapeShellArg checkedSubject.version)
    ]
  );

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
    ++ lib.optionals (excludes != [ ]) (lib.map (e: "--exclude ${e}") excludes)
    # Only the store paths are of interest. They are built for the runtime dependencies anyway.
    ++ lib.map (path: "--extra-path ${builtins.unsafeDiscardStringContext "${path}"}") extraPaths
    ++ subjectArgs;
in
runCommand "${drv.name}.cdx.json"
  {
    nativeBuildInputs = [
      transformer
      cyclonedx-cli
      jq
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
      --output-file=converted.cdx.json

    jq --from-file ${./finish-bom.jq} \
      --slurpfile options ${builtins.toFile "bom-options.json" (builtins.toJSON finishOptions)} \
      converted.cdx.json > $out
  ''
