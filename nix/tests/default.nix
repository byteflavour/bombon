{
  pkgs,
  buildBom,
  passthruVendoredSbom,
}:

let
  rustPassthru = pkg: passthruVendoredSbom.rust pkg { inherit pkgs; };
  npmPassthru = pkg: passthruVendoredSbom.npm pkg { inherit pkgs; };
  pnpmPassthru = pkg: passthruVendoredSbom.pnpm pkg { inherit pkgs; };
  goPassthru = pkg: passthruVendoredSbom.go pkg { inherit pkgs; };

  buildtimeOptions = {
    includeBuildtimeDependencies = true;
  };

  # This list cannot grow indefinitely because building a Bom requires all
  # builtime dependencies to be downloaded or built. A lot of time is spent
  # evaluating, downloading, and building.
  testDerivations = with pkgs; [
    {
      name = "hello";
      drv = hello;
      options = { };
      # The homepage of a package is its creator. The property it is passed along in is gone.
      assertion = ''
        def website: [ .externalReferences[]? | select(.type == "website") | .url ];
        (.metadata.component | (website | length) == 1 and .manufacturer.url == website)
        # Nothing is said about the SBOM itself unless it is given
        and (.metadata | (has("timestamp") or has("manufacturer")) | not)
        and all(
          .components[];
          (.manufacturer.url // [ ]) == website
          and (.properties | any(.name == "bombon:origin"))
          and (.properties | all(.name != "bombon:manufacturer-url"))
        )
        # Whether the dependencies are complete is not known, for what the SBOM describes and
        # for every component
        and (.compositions | length == 1 and .[0].aggregate == "unknown")
        and (.compositions[0].dependencies | sort)
          == ([ .metadata.component."bom-ref", .components[]."bom-ref" ] | unique)
      '';
    }
    # What is given about the SBOM and its subject
    {
      name = "document-metadata";
      drv = hello;
      options = {
        timestamp = "2026-01-31T12:00:00Z";
        creator = {
          name = "Example";
          email = "sbom@example.org";
        };
        subject = {
          name = "greeter";
          version = "1.0";
          creator = {
            url = "https://example.org";
          };
        };
      };
      assertion = ''
        .metadata.component."bom-ref" as $subject
        | .metadata.timestamp == "2026-01-31T12:00:00Z"
        and .metadata.manufacturer == { name: "Example", contact: [ { email: "sbom@example.org" } ] }
        and any(.metadata.tools.components[]; .name == "bombon")
        and (
          .metadata.component
          | .name == "greeter"
            and .version == "1.0"
            and .purl == "pkg:nix/greeter@1.0"
            and .manufacturer == { url: [ "https://example.org" ] }
        )
        # It is still the derivation that is described
        and ($subject | test("^[a-z0-9]{32}-hello-"))
        and any(.components[]; ."bom-ref" == $subject and .name == "hello")
        and any(.dependencies[]; .ref == $subject and (.dependsOn | length > 0))
      '';
    }
    {
      name = "hello-buildtime";
      drv = hello;
      options = buildtimeOptions;
    }

    {
      name = "python3";
      drv = python3;
      options = { };
    }
    # Sacrificed to make space for the LLVM test
    # {
    #   name = "python3-buildtime";
    #   drv = python3;
    #   options = buildtimeOptions;
    # }

    # Takes too much storage for GitHub Actions
    # weird string license in buildtimeDependencies
    # {
    #   name = "poetry";
    #   drv = poetry;
    #   options = { };
    # }
    # Takes too much storage for GitHub Actions
    # {
    #   name = "poetry-buildtime";
    #   drv = poetry;
    #   options = buildtimeOptions;
    # }

    {
      name = "git";
      drv = git;
      options = { };
    }
    {
      name = "git-buildtime";
      drv = git;
      options = buildtimeOptions;
    }

    {
      name = "git-extra-paths";
      drv = git;
      options = {
        extraPaths = [ hello ];
      };
      # git does not refer to hello but what the SBOM describes depends on it
      assertion = ''
        (.components[] | select(.name == "hello") | ."bom-ref") as $hello
        | .metadata.component."bom-ref" as $subject
        | any(.dependencies[]; .ref == $subject and (.dependsOn | index($hello)))
      '';
    }
    # Takes too much storage for GitHub Actions
    # {
    #   name = "git-extra-paths-buildtime";
    #   drv = git;
    #   options = buildtimeOptions // {
    #     extraPaths = [ poetry ];
    #   };
    # }

    {
      name = "cloud-hypervisor";
      drv = rustPassthru cloud-hypervisor;
      options = { };
    }
    {
      name = "cloud-hypervisor-buildtime";
      drv = rustPassthru cloud-hypervisor;
      options = buildtimeOptions;
    }

    {
      name = "pyright";
      drv = npmPassthru pyright;
      options = { };
    }
    {
      name = "pyright-buildtime";
      drv = npmPassthru pyright;
      options = buildtimeOptions;
    }

    {
      name = "taze";
      drv = pnpmPassthru taze;
      options = { };
    }
    {
      name = "taze-buildtime";
      drv = pnpmPassthru taze;
      options = buildtimeOptions;
    }

    {
      name = "lessc";
      drv = pnpmPassthru lessc;
      options = { };
    }

    # The Go modules are vendored into a directory, so their licenses are detected from the
    # license files in it and are evidence
    {
      name = "age";
      drv = goPassthru age;
      options = { };
      assertion = ''
        [ .components[] | select((.purl // "") | startswith("pkg:golang/")) ]
        | length > 0
        and all(.[]; (has("licenses") | not) and (.evidence.licenses | length > 0))
      '';
    }
    {
      name = "age-buildtime";
      drv = goPassthru age;
      options = buildtimeOptions;
    }
    # The Go modules are available as a module proxy while building, so the licenses that are
    # detected in their sources are evidence
    {
      name = "pigeon";
      drv = goPassthru pigeon;
      options = { };
      assertion = ''
        [ .components[] | select((.purl // "") | startswith("pkg:golang/")) ]
        | length > 0
        and all(
          .[];
          (has("licenses") | not)
          and (.evidence.licenses | length > 0)
          and all(.evidence.licenses[]; .license.id | type == "string")
        )
      '';
    }

    # Multiple src urls
    {
      name = "kexec-tools";
      drv = kexec-tools;
      options = { };
    }

    # compound license
    {
      name = "llvm";
      drv = llvm;
      options = { };
    }

    # Dependencies that are only referred to in a string
    {
      name = "string-context";
      drv = writeText "string-context-1.0" "${jq}/bin/jq";
      options = { };
      # jq depends on the lib output of oniguruma
      assertion = ''
        (.components[] | select(.name == "oniguruma" and .version != "") | ."bom-ref") as $ref
        | ($ref | endswith("-lib"))
          and any(.dependencies[]; .ref == $ref)
          and any(.dependencies[]; .dependsOn | index($ref))
          # Nothing is known about who created a dependency that is described by its recipe
          and all(
            .components[] | select(.properties | any(.name == "bombon:origin" and .value == "recipe"));
            has("manufacturer") | not
          )
      '';
    }

    # A dependency that is referred to through a store path that is not a component, like the
    # packages of a NixOS system that are referred to in its unit files
    {
      name = "indirect-reference";
      drv = writeText "indirect-reference-1.0" "${writeText "unit" "${jq}/bin/jq"}";
      options = { };
      assertion = ''
        .metadata.component."bom-ref" as $subject
        | (.dependencies | map({ (.ref): (.dependsOn // [ ]) }) | add) as $graph
        | ([ $subject | recurse($graph[.][]) ] | unique) as $reachable
        | ([ .components[] | select(.name == "jq") | ."bom-ref" ]) as $jq
        | any($jq[]; . as $ref | $graph[$subject] | index($ref))
        and all(.components[]; ."bom-ref" as $ref | $reachable | index($ref))
        and all(.components[]; .name != "unit")
      '';
    }

    # An excluded dependency: what refers to it, also through a store path that is not a
    # component, is known to lack a dependency
    {
      name = "excluded-dependency";
      drv = writeText "excluded-dependency-1.0" "${writeText "unit" "${jq}/bin/jq"}";
      options = {
        excludes = [ "jq.+bin" ];
      };
      assertion = ''
        .metadata.component."bom-ref" as $subject
        | (.compositions | map({ (.aggregate): .dependencies }) | add) as $completeness
        | all(.components[]; ."bom-ref" | test("jq.+bin") | not)
        and (.compositions | map(.aggregate)) == [ "unknown", "incomplete" ]
        and $completeness.incomplete == [ $subject ]
        and ($completeness.unknown | sort) == ([ .components[]."bom-ref" ] | sort)
        and (.components | length > 0)
      '';
    }

    # Metadata for a dependency that is only referred to in a string. A package that is not a
    # dependency (hello) adds nothing, not even as a buildtime dependency.
    {
      name = "metadata-from";
      drv = writeText "metadata-from-1.0" "${jq}/bin/jq";
      options = buildtimeOptions // {
        metadataFrom = [
          jq
          hello
        ];
      };
      assertion = ''
        ([ .components[] | select(.name == "jq") ]
          | length > 0 and all(
            (.licenses | length > 0) and (.properties | any(.name == "bombon:origin" and .value == "package"))
          ))
        and ([ .components[] | select(.name == "hello") ] | length == 0)
      '';
    }

    # Packages for build recipes are looked up in a package set
    {
      name = "package-sets";
      drv = writeText "package-sets-1.0" "${jq}/bin/jq";
      options = {
        packageSets = [ pkgs ];
      };
      # jq is looked up, oniguruma is found because jq depends on it
      assertion = ''
        [ .components[] | select(.name == "jq" or .name == "oniguruma") ]
        | length >= 2 and all(.licenses | length > 0)
      '';
    }

    # The package set of a language prefixes the names of its packages
    {
      name = "package-sets-scoped";
      drv = writeText "package-sets-scoped-1.0" "${python3Packages.requests}";
      options = {
        packageSets = [ python3Packages ];
      };
      assertion = ''
        [ .components[] | select(.name == "requests" or .name == "urllib3") ]
        | length >= 2 and all(
          (.licenses | length > 0) and (.properties | any(.name == "bombon:origin" and .value == "package"))
        )
      '';
    }

    # Metadata of a package that is built from the same source
    {
      name = "same-source";
      drv = writeText "same-source-1.0" "${
        jq.overrideAttrs (_: {
          SOME_FLAG = "1";
        })
      }/bin/jq";
      options = {
        packageSets = [ pkgs ];
      };
      assertion = ''
        .components[] | select(.name == "jq")
        | (.licenses | length > 0)
          and (.properties | any(.name == "bombon:origin" and .value == "recipe+same-source-package"))
      '';
    }
  ];

  cycloneDxVersion = "1.7";

  cycloneDxSpec = pkgs.fetchFromGitHub {
    owner = "CycloneDX";
    repo = "specification";
    # Potentially download a newer version than the one being checked because
    # it includes updated SPDX identifiers. They are stored in a file that just
    # lives alongside the CycloneDX schema file.
    rev = cycloneDxVersion;
    sha256 = "sha256-30u5dqNj3xgVO2MONdHJIoqwdgFSbyOwBQQc0AnoDWM=";
  };

  # Additionally to validating the Bom, an assertion on its content can be given
  # as a jq filter that has to evaluate to true.
  buildBomAndValidate =
    drv: options: assertion:
    pkgs.runCommand "${drv.name}-bom-validation"
      {
        nativeBuildInputs = [
          pkgs.check-jsonschema
          pkgs.jq
        ];
        inherit assertion;
      }
      ''
        sbom="${buildBom drv options}"
        check-jsonschema \
          --schemafile "${cycloneDxSpec}/schema/bom-${cycloneDxVersion}.schema.json" \
          --base-uri "${cycloneDxSpec}/schema/bom-${cycloneDxVersion}.schema.json" \
          "$sbom"
        if [ -n "$assertion" ]; then
          jq --exit-status "$assertion" "$sbom"
        fi
        ln -s $sbom $out
      '';

  genAttrsFromDrvs =
    drvs: f:
    builtins.listToAttrs (
      map (d: pkgs.lib.nameValuePair d.name (f d.drv d.options (d.assertion or ""))) drvs
    );
in
genAttrsFromDrvs testDerivations buildBomAndValidate
