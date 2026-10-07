# This returns a JSON file that maps the store path of each build recipe (`.drv` file) in the
# build closure of drv to the content of that recipe.
#
# The recipes state what each store path is, also for dependencies that cannot be found via
# `drvAttrs` because they are only referred to in a string.
#
# The recipes are read while evaluating. The resulting file does not refer to any store path, so
# that neither the recipes themselves nor the sources they refer to become inputs of a build.
{
  lib,
}:

let

  wrap = recipe: rec {
    key = recipe;
    content = builtins.readFile recipe;
    # The recipes a recipe depends on are part of the string context of its content.
    inputRecipes = lib.filter (lib.hasSuffix ".drv") (lib.attrNames (builtins.getContext content));
  };

in

drv: extraPaths:

let

  roots = map (d: builtins.unsafeDiscardStringContext d.drvPath) (
    lib.filter lib.isDerivation ([ drv ] ++ extraPaths)
  );

  recipes = builtins.genericClosure {
    startSet = map wrap roots;
    operator = item: map wrap item.inputRecipes;
  };

in

builtins.toFile "${drv.name}-recipes.json" (
  builtins.toJSON (
    lib.listToAttrs (
      map (item: lib.nameValuePair item.key (builtins.unsafeDiscardStringContext item.content)) recipes
    )
  )
)
