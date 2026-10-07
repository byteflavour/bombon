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

    {
      name = "age";
      drv = goPassthru age;
      options = { };
    }
    {
      name = "age-buildtime";
      drv = goPassthru age;
      options = buildtimeOptions;
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
