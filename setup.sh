#!/data/data/com.termux/files/usr/bin/bash

# Clear screen
clear
echo "[*] Setting up Payback tool in Termux..."
sleep 1

# Update and upgrade Termux
pkg update -y && pkg upgrade -y

# Install base development tools
pkg install -y python clang rust git libjpeg-turbo libpng freetype openssl libffi nmap

# Upgrade pip, setuptools, wheel
pip install --upgrade pip setuptools wheel

# Clear pip cache to avoid old junk
pip cache purge

# Install required Python packages (including cvss)
CFLAGS="-Wno-error=implicit-function-declaration" pip install \
    pillow cryptography requests colorama rich fpdf cvss

echo ""
echo "✅ DONE! Payback tool is ready."
echo "👉 Run it like this: python payback.py"
echo ""
