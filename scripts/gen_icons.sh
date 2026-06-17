#!/usr/bin/env bash
# Regenerate EVERY platform's app icon from two canonical sources:
#   img/goblin-icon.png        the gradient app icon (yellow gradient + black mascot)
#   img/goblin-mark-black.svg  the black mascot mark, vector, transparent bg
#                              (mirror of site/assets/goblin-mark-black.svg)
#
# Square icons (desktop window, Linux AppImage, Android launcher, Windows .ico,
# macOS .icns) come from the gradient PNG. The Android *adaptive* foreground is
# the black mascot on transparency, composited by the OS over the yellow
# background color (res/values/ic_launcher_background.xml = #FFD60A) — which
# reproduces the gradient icon's look.
#
# Requires ImageMagick (magick) and python3 (for the .icns container).
set -euo pipefail
cd "$(dirname "$0")/.."

ICON=img/goblin-icon.png
MARK=img/goblin-mark-black.svg
RES=android/app/src/main/res

# --- Desktop window icon (egui, src/main.rs) + Linux AppImage AppDir icon ---
magick "$ICON" -resize 256x256 PNG32:img/icon.png
cp img/icon.png linux/Goblin.AppDir/goblin.png

# --- Android launcher icons (gradient square) + adaptive foreground (mascot) ---
declare -A SIZES=(    [mdpi]=48  [hdpi]=72  [xhdpi]=96  [xxhdpi]=144 [xxxhdpi]=192 )
declare -A FG_SIZES=( [mdpi]=108 [hdpi]=162 [xhdpi]=216 [xxhdpi]=324 [xxxhdpi]=432 )
for d in mdpi hdpi xhdpi xxhdpi xxxhdpi; do
  s=${SIZES[$d]}; fg=${FG_SIZES[$d]}
  # Mascot fills ~60% of the adaptive canvas — inside the ~61% safe zone, so no
  # launcher mask (circle/squircle) ever clips it.
  art=$(( fg * 60 / 100 ))
  magick "$ICON" -resize "${s}x${s}"   PNG32:"$RES/mipmap-$d/ic_launcher.png"
  magick "$ICON" -resize "${s}x${s}"   PNG32:"$RES/mipmap-$d/ic_launcher_round.png"
  magick -background none "$MARK" -resize "${art}x${art}" \
    -gravity center -extent "${fg}x${fg}" PNG32:"$RES/mipmap-$d/ic_launcher_foreground.png"
done

# --- Windows installer + file-type icon (WiX wix/Product.ico) ---
magick "$ICON" -define icon:auto-resize=256,128,64,48,32,24,16 wix/Product.ico

# --- macOS app bundle icon (Goblin.app) ---
python3 scripts/make-icns.py "$ICON" macos/Goblin.app/Contents/Resources/AppIcon.icns

echo "icons generated from $ICON + $MARK"
