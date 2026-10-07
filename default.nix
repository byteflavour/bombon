{ pkgs }:
pkgs.lib.makeScope pkgs.newScope (self: {
  passthruVendoredSbom = import ./nix/passthru-vendored.nix;

  # It's useful to have these exposed for debugging. However, they are not a
  # public interface.
  __internal = {
    buildtimeDependencies = self.callPackage ./nix/buildtime-dependencies.nix {
      inherit (self.__internal) recipeClosure;
    };
    runtimeDependencies = self.callPackage ./nix/runtime-dependencies.nix { };
    recipeClosure = self.callPackage ./nix/recipe-closure.nix { };
    recipes = self.callPackage ./nix/recipes.nix {
      inherit (self.__internal) recipeClosure;
    };
    transformerWithoutSbom = self.callPackage ./nix/packages/transformer.nix { };
  };

  transformer = self.passthruVendoredSbom.rust self.__internal.transformerWithoutSbom {
    inherit pkgs;
  };

  buildBom = self.callPackage ./nix/build-bom.nix {
    inherit (self.__internal) buildtimeDependencies runtimeDependencies recipes;
  };
})
