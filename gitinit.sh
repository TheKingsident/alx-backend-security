#!/usr/bin/env bash
echo "# alx-backend-security" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin git@github.com:TheKingsident/alx-backend-security.git
git push -u origin main