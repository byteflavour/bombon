let
  sources = import ../lon.nix;
  pkgs = import sources.nixpkgs { };
in
pkgs.mkShell {
  packages = [
    pkgs.nix-eval-jobs
    pkgs.jq
  ];

  shellHook = ''
    eval-checks() {
      nix-eval-jobs release.nix --check-cache-status | jq -s 'map({attr, isCached})'
    }

    # Evaluate SBOMs through a flake that has this repository as an input, i.e. purely, as
    # users of the flake do. The checks are built with nix-build, which evaluates impurely.
    eval-pure() {
      local repository flake system
      repository=$(git rev-parse --show-toplevel)
      flake=$(mktemp -d)
      system=$(nix eval --impure --raw --expr builtins.currentSystem)
      cat > "$flake/flake.nix" <<EOF
    {
      inputs.bombon.url = "git+file://$repository";
      outputs = { bombon, ... }:
        let
          pkgs = bombon.inputs.nixpkgs.legacyPackages.$system;
          inherit (bombon.lib.$system) buildBom;
          stringContext = pkgs.writeText "string-context-1.0" "\''${pkgs.jq}/bin/jq";
        in
        {
          plain = buildBom pkgs.hello { };
          packageSets = buildBom stringContext {
            metadataFrom = [ pkgs.jq ];
            packageSets = [ pkgs ];
          };
        };
    }
    EOF
      local result=0
      echo "without packageSets, import from derivation disabled:"
      nix eval --no-write-lock-file --raw --option allow-import-from-derivation false \
        "$flake#plain.drvPath" || result=1
      echo
      echo "with packageSets:"
      nix eval --no-write-lock-file --raw "$flake#packageSets.drvPath" || result=1
      echo
      echo "with packageSets, import from derivation disabled (must fail):"
      if nix eval --no-write-lock-file --raw --option allow-import-from-derivation false \
        "$flake#packageSets.drvPath" 2> "$flake/error"; then
        echo "evaluated, but it needs import from derivation"
        result=1
      elif grep -q allow-import-from-derivation "$flake/error"; then
        echo "failed as expected"
      else
        cat "$flake/error"
        result=1
      fi
      rm -rf "$flake"
      return $result
    }
  '';
}
