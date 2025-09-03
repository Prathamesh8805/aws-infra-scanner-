#!/bin/bash

# Create a virtual environment
echo "Creating a virtual environment..."
python3 -m venv venv

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install the package
echo "Installing infra-scanner..."
pip install -e .

# Test the installation
echo "Testing installation..."
infra-scanner --help

echo "Installation complete!"
echo "You can now use 'infra-scanner scan' to scan your AWS infrastructure."
echo "To activate the virtual environment in the future, run: source venv/bin/activate"
