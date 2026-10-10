{ pkgs ? import <nixpkgs> {} }:

let
  libraries = with pkgs; [
    libglvnd
    libGLU
    libxkbcommon
    wayland
    libx11
    libxcursor
    libxi
    libxrandr
    libxcb
    libXext
    libXfixes
    libXrender
    libXtst
  ];
in
pkgs.mkShell {
  buildInputs = libraries;
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath libraries;
}
