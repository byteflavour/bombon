# This returns a derivation that reads the build recipes (`.drv` files) in the build closure of drv
# and extraPaths and writes two JSON files:
#
#  - recipes.json: the content of each recipe, by its store path.
#  - inputs.json: the recipes each recipe depends on directly, by its store path.
#
# The recipes state what each store path is, also for dependencies that cannot be found via
# `drvAttrs` because they are only referred to in a string.
#
# The recipes are read while building because pure evaluation does not allow reading them. Their
# outputs are not built: only the recipes themselves are inputs.
{
  lib,
  runCommand,
  transformer,
}:

drv: extraPaths:

runCommand "${drv.name}-recipes"
  {
    __structuredAttrs = true;
    roots = map (d: builtins.unsafeDiscardOutputDependency d.drvPath) (
      lib.filter lib.isDerivation ([ drv ] ++ extraPaths)
    );

    # The index names the recipes, but does not need them. Building it is cheaper than sending
    # the recipes to another machine.
    unsafeDiscardReferences.out = true;
    preferLocalBuild = true;
    allowSubstitutes = false;

    nativeBuildInputs = [ transformer ];
  }
  ''
    bombon-transformer recipe-index --output "$out" "''${roots[@]}"
  ''
