{
  description = "Eenvoudige Python development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      devShells = forEachSupportedSystem ({ pkgs }:
        let
                      # Define the PyPI rtsp package
                      rtsp = pkgs.python3Packages.buildPythonPackage rec {
                        pname = "rtsp";
                        version = "2.0.3";
                        pyproject = true;

                        src = pkgs.python3Packages.fetchPypi {
                          inherit pname version;
                          sha256 = "eb19a2104fafba1fefec5d23fb04a79441ec12f13914d3bb1c316484cee597bd";
                        };

                        build-system = [
                          pkgs.python3Packages.hatchling
                        ];

                        dependencies = with pkgs.python3Packages; [
                          av
                          numpy
                          pillow
                        ];

                        doCheck = false;
                      };
                    in
                    {
        default = pkgs.mkShell {
          packages = with pkgs; [
            ffmpeg
            (python3.withPackages (ps: with ps; [
              # Voeg hier eventuele Python bibliotheken toe, bijv:
              # numpy
              # requests
              pycryptodome
              cryptography
              rtsp
              opencv-python
              requests
            ]))
          ];

          shellHook = ''
            echo "Python devshell geactiveerd!"
            python --version
          '';
        };
      });
    };
}
