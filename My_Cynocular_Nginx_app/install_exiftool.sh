#!/bin/bash

# Set the version you want to download
VERSION="12.62"

# Download the ExifTool tarball
echo "Downloading ExifTool version $VERSION..."
wget https://exiftool.org/Image-ExifTool-$VERSION.tar.gz -O /tmp/Image-ExifTool-$VERSION.tar.gz

# Change to the /tmp directory
cd /tmp

# Extract the tarball
echo "Extracting ExifTool tarball..."
tar -zxvf Image-ExifTool-$VERSION.tar.gz

# Change to the extracted directory
cd Image-ExifTool-$VERSION

# Install ExifTool
echo "Installing ExifTool..."
perl Makefile.PL
make
sudo make install

# Clean up
echo "Cleaning up..."
cd ..
rm -rf Image-ExifTool-$VERSION
rm Image-ExifTool-$VERSION.tar.gz

# Verify installation
echo "Verifying installation..."
exiftool -ver

echo "ExifTool installation completed successfully!"
