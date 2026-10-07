# This returns the build recipes (`.drv` files) in the build closure of drv as a list. Elements in
# the list have three fields:
#
#  - key: the store path of the recipe.
#  - content: the content of the recipe.
#  - inputRecipes: the store paths of the recipes the recipe depends on.
#
# The recipes are read while evaluating.
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

in

builtins.genericClosure {
  startSet = map wrap roots;
  operator = item: map wrap item.inputRecipes;
}
