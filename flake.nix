{
  description = "ClipTown Rust backend agent-first development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        agentCheck = pkgs.writeShellApplication {
          name = "agent-check";
          runtimeInputs =
            (with pkgs; [
              # encrypted env files — env/enc/*.env.enc (sops + age), see env/README.md
              sops
              age
              just
              actionlint
              bash
              binutils
              cacert
              cargo-audit
              coreutils
              gcc
              git
              gnumake
              gnugrep
              gnused
              nixfmt-rfc-style
              openssl
              pkg-config
              rsync
              rustup
              shellcheck
              shfmt
            ])
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.libiconv ];
          text = builtins.readFile ./.nix/agent-check.sh;
        };
      in
      {
        devShells.default = import ./.nix/dev-shell.nix { inherit pkgs agentCheck; };

        packages = {
          default = agentCheck;
          agent-check = agentCheck;
        };

        apps = {
          default = flake-utils.lib.mkApp { drv = agentCheck; };
          agent-check = flake-utils.lib.mkApp { drv = agentCheck; };
        };

        checks.agent-check = agentCheck;
        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
