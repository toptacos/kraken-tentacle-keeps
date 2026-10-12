#!/bin/sh
# Dispatch: compiled keeps binary if present, else python3.
# stdin JSON → stdout JSON. Core never imports this.
set -eu
DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
OS=$(uname -s | tr 'A-Z' 'a-z')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac
BIN=""
case "$OS" in
  linux)  BIN="$DIR/dist/keeps-linux-$ARCH" ;;
  darwin) BIN="$DIR/dist/keeps-darwin-$ARCH" ;;
  msys*|mingw*|cygwin*) BIN="$DIR/dist/keeps-windows-$ARCH.exe" ;;
esac
if [ -n "$BIN" ] && [ -f "$BIN" ] && [ -x "$BIN" ]; then
  exec "$BIN"
fi
if command -v python3 >/dev/null 2>&1; then
  exec python3 "$DIR/handler.py"
fi
printf '%s\n' '{"v":1,"id":null,"ok":false,"error":{"code":"no_runtime","message":"build dist/ or install python3"}}'
exit 0
