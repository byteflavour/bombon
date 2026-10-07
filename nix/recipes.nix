# This returns a JSON file that maps the store path of each build recipe (`.drv` file) in the
# build closure of drv to the content of that recipe.
#
# The recipes state what each store path is, also for dependencies that cannot be found via
# `drvAttrs` because they are only referred to in a string.
#
# The resulting file does not refer to any store path, so that neither the recipes themselves nor
# the sources they refer to become inputs of a build.
{
  lib,
  recipeClosure,
}:

drv: extraPaths:

builtins.toFile "${drv.name}-recipes.json" (
  builtins.toJSON (
    lib.listToAttrs (
      map (item: lib.nameValuePair item.key (builtins.unsafeDiscardStringContext item.content)) (
        recipeClosure drv extraPaths
      )
    )
  )
)
