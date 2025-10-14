#!/bin/bash
# Caido Hunt - Quick Deployment Script
# Author: Llakterian (llakterian@gmail.com)

echo "======================================="
echo "   Caido Hunt v2.0 - GitHub Deploy"
echo "======================================="
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
fi

echo "Adding all files..."
git add .

echo ""
echo "Creating commit..."
git commit -m "feat: Caido Hunt v2.0 - Production ready bug bounty scanner

- Complete vulnerability detection suite (20+ types)
- Multiple interfaces: CLI and GUI
- Comprehensive documentation
- Clean project structure  
- Full attribution to Llakterian

Author: Llakterian (llakterian@gmail.com)
Repository: https://github.com/llakterian/caido-hunt"

echo ""
echo "Adding remote (if not already added)..."
git remote add origin https://github.com/llakterian/caido-hunt.git 2>/dev/null || echo "Remote already exists"

echo ""
echo "Pushing to GitHub..."
git branch -M main
git push -u origin main

echo ""
echo "Creating release tag..."
git tag -a v2.0.0 -m "Caido Hunt v2.0.0 - Production Release"
git push origin v2.0.0

echo ""
echo "======================================="
echo "   ✅ DEPLOYMENT COMPLETE!"
echo "======================================="
echo ""
echo "Repository: https://github.com/llakterian/caido-hunt"
echo "Next steps:"
echo "1. Visit the repository and create a GitHub Release"
echo "2. Configure repository settings (topics, description)"
echo "3. Announce to the community!"
echo ""
echo "Built by Llakterian | llakterian@gmail.com"
