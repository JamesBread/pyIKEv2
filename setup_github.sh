#!/bin/bash

# Script to initialize and push pyIKEv2 to GitHub
# 
# Prerequisites:
# 1. Create the repository on GitHub first:
#    - Go to https://github.com
#    - Click "New repository"
#    - Name it "pyIKEv2"
#    - Don't initialize with README (we already have one)
#    - Create repository
#
# 2. Then run this script

echo "Setting up pyIKEv2 GitHub repository..."

# Initialize git repository if not already initialized
if [ ! -d .git ]; then
    echo "Initializing git repository..."
    git init
else
    echo "Git repository already initialized"
fi

# Add all files to git
echo "Adding files to git..."
git add .

# Create initial commit
echo "Creating initial commit..."
git commit -m "Initial commit: pyIKEv2 - Python3 implementation of IKEv2 (RFC 7296)

- Complete IKEv2 protocol implementation
- Full RFC 7296 compliance
- Modern cryptographic algorithms support
- Comprehensive test suite
- CLI tools and daemon
- YAML/JSON configuration

Created with AI assistance from Claude Code"

# Add remote origin
echo "Adding remote origin..."
git remote add origin https://github.com/JamesBread/pyIKEv2.git

# Set main branch
git branch -M main

# Push to GitHub
echo "Pushing to GitHub..."
echo "You may be prompted for your GitHub credentials or personal access token"
git push -u origin main

echo "Done! Repository pushed to https://github.com/JamesBread/pyIKEv2"
echo ""
echo "Next steps:"
echo "1. Visit https://github.com/JamesBread/pyIKEv2 to view your repository"
echo "2. Consider adding topics: ikev2, ipsec, vpn, python, rfc7296"
echo "3. Set up GitHub Actions for automated testing"
echo "4. Add badges to README.md for build status, license, etc."