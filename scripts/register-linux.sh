#!/bin/sh

if ! which reprounzip-qt &>/dev/null; then
    echo "reprounzip-qt is not in PATH" >&2
    exit 1
fi

# Install x-reprozip mimetype
cat >/tmp/reprozip-mime.xml <<'END'
<?xml version="1.0"?>
<mime-info xmlns='http://www.freedesktop.org/standards/shared-mime-info'>
  <mime-type type="application/x-reprozip">
    <comment>ReproZip Package</comment>
    <glob pattern="*.rpz"/>
  </mime-type>
</mime-info>
END
xdg-mime install /tmp/reprozip-mime.xml
update-mime-database "$HOME/.local/share/mime"

# Install desktop file
mkdir -p "$HOME/.local/share/applications"
cat >"$HOME/.local/share/applications/reprounzip.desktop" <<END
[Desktop Entry]
Name=ReproUnzip
Exec=$(which reprounzip-qt) %f
Type=Application
MimeType=application/x-reprozip
END
update-desktop-database "$HOME/.local/share/applications"

# Install icon
if ! [ -d "$HOME/.local/share/icons/hicolor/48x48/mimetypes" ]; then
    mkdir "$HOME/.local/share/icons/hicolor/48x48/mimetypes"
fi
cp "$(dirname "$0")/reprounzip-qt/icon.png" \
    "$HOME/.local/share/icons/hicolor/48x48/mimetypes/application-x-reprozip.png"
update-icon-caches "$HOME/.local/share/icons/hicolor"
