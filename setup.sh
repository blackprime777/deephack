# Update and upgrade Termux
pkg update -y && pkg upgrade -y

# Install base development tools
pkg install -y python clang rust git libjpeg-turbo libpng freetype openssl libffi

# Upgrade pip, setuptools, wheel
pip install --upgrade pip setuptools wheel

# Clear pip cache to avoid old junk
pip cache purge

# Install required Python packages (your tool depends on these)
CFLAGS="-Wno-error=implicit-function-declaration" pip install \
    pillow cryptography requests colorama rich fpdf

echo ""
echo "✅ DONE! You can now run your tool like this:"
echo "👉 python payback.py"
echo ""
