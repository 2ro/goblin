#!/usr/bin/env bash
# Generate all Goblin app icons from img/goblin-icon.png (app icon)
# and img/goblin-mask.png (black mascot art on transparency).
# Requires ImageMagick (magick).
set -euo pipefail
cd "$(dirname "$0")/.."

ICON=img/goblin-icon.png
MASK=img/goblin-mask.png
RES=android/app/src/main/res

# Desktop window icon + in-app embeds.
magick "$ICON" -resize 256x256 img/icon.png
magick "$ICON" -resize 512x512 img/goblin-icon-512.png
magick "$MASK" -channel RGB -fill white -colorize 100 img/goblin-mask-white.png
magick img/goblin-mask-white.png -resize 128x128 img/goblin-mask-128.png
magick img/goblin-mask-white.png -resize 64x64 img/goblin-mask-64.png

# Android launcher icons.
declare -A SIZES=( [mdpi]=48 [hdpi]=72 [xhdpi]=96 [xxhdpi]=144 [xxxhdpi]=192 )
declare -A FG_SIZES=( [mdpi]=108 [hdpi]=162 [xhdpi]=216 [xxhdpi]=324 [xxxhdpi]=432 )
for d in mdpi hdpi xhdpi xxhdpi xxxhdpi; do
  s=${SIZES[$d]}; fg=${FG_SIZES[$d]}
  # mascot occupies ~52% of the adaptive canvas (safe zone is 66%)
  art=$(( fg * 52 / 100 ))
  magick "$ICON" -resize ${s}x${s} "$RES/mipmap-$d/ic_launcher.png"
  magick "$ICON" -resize ${s}x${s} "$RES/mipmap-$d/ic_launcher_round.png"
  magick "$MASK" -resize ${art}x${art} -background none \
    -gravity center -extent ${fg}x${fg} "$RES/mipmap-$d/ic_launcher_foreground.png"
done

echo "icons generated"
