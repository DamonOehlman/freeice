{
  description = "A liveness check for the STUN/TURN servers freeice ships";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      each = function:
        nixpkgs.lib.genAttrs systems (system: function nixpkgs.legacyPackages.${system});
    in
    {
      packages = each (pkgs: {
        ice-check = pkgs.rustPlatform.buildRustPackage {
          pname = "ice-check";
          version = "0.1.0";
          src = ./tools/ice-check;
          cargoLock.lockFile = ./tools/ice-check/Cargo.lock;
        };

        default = self.packages.${pkgs.stdenv.hostPlatform.system}.ice-check;
      });

      devShells = each (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc pkgs.clippy pkgs.rustfmt ];
        };
      });

      checks = each (pkgs: {
        ice-check = self.packages.${pkgs.stdenv.hostPlatform.system}.ice-check;
      });
    };
}
