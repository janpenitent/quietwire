# SPDX-FileCopyrightText: 2026 Janier Rodríguez <jrodriguez@virtualcable.es>
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "QUIETWIRE reproducible builds";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      }));
      pinnedToolchain = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
    in
    {
      packages = forAllSystems (pkgs:
        let
          rustPlatform = pkgs.makeRustPlatform {
            cargo = pinnedToolchain pkgs;
            rustc = pinnedToolchain pkgs;
          };
        in
        {
          default = rustPlatform.buildRustPackage {
            pname = "quietwire-node";
            version = "0.0.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "--package" "quietwire-node" ];
            doCheck = false;
            meta = {
              description = "Headless QUIETWIRE relay daemon";
              homepage = "https://github.com/janpenitent/quietwire";
              license = pkgs.lib.licenses.asl20;
            };
          };
        });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pinnedToolchain pkgs)
            pkgs.cargo-nextest
            pkgs.cargo-deny
            pkgs.cargo-audit
            pkgs.reuse
            pkgs.python312
          ];
        };
      });
    };
}
