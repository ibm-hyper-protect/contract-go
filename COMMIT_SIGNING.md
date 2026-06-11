# Commit Signing Guide

This repository requires all commits to be signed with GPG or SSH keys. This ensures the authenticity and integrity of code contributions.

## Why Commit Signing?

- **Authentication**: Proves commits are from legitimate team members
- **Integrity**: Detects if commits have been tampered with
- **Non-repudiation**: Authors cannot deny making signed commits
- **Compliance**: Meets security requirements for regulated industries

## Quick Start

### Option 1: GPG Signing (Recommended)

#### 1. Generate a GPG Key

```bash
# Generate a new GPG key
gpg --full-generate-key

# Follow the prompts:
# - Select RSA and RSA (default)
# - Key size: 4096 bits
# - Expiration: 1 year (recommended)
# - Enter your name and email (must match your GitHub email)
```

#### 2. List Your GPG Keys

```bash
gpg --list-secret-keys --keyid-format=long
```

Output example:
```
sec   rsa4096/3AA5C34371567BD2 2026-01-15 [SC]
      1234567890ABCDEF1234567890ABCDEF12345678
uid                 [ultimate] Your Name <your.email@example.com>
ssb   rsa4096/42B317FD4BA89E7A 2026-01-15 [E]
```

Your GPG key ID is: `3AA5C34371567BD2`

#### 3. Export Your Public Key

```bash
# Replace YOUR_KEY_ID with your actual key ID
gpg --armor --export 3AA5C34371567BD2
```

#### 4. Add GPG Key to GitHub

1. Copy the entire GPG key output (including `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----END PGP PUBLIC KEY BLOCK-----`)
2. Go to GitHub: **Settings** → **SSH and GPG keys** → **New GPG key**
3. Paste your public key and click **Add GPG key**

#### 5. Configure Git to Sign Commits

```bash
# Set your GPG key for signing
git config --global user.signingkey 3AA5C34371567BD2

# Enable automatic commit signing
git config --global commit.gpgsign true

# Optional: Sign tags by default
git config --global tag.gpgsign true
```

#### 6. Make a Signed Commit

```bash
# Commits will now be signed automatically
git commit -m "feat: add new feature"

# Or explicitly sign a commit
git commit -S -m "feat: add new feature"
```

### Option 2: SSH Signing (Git 2.34+)

#### 1. Generate SSH Key (if you don't have one)

```bash
ssh-keygen -t ed25519 -C "your.email@example.com"
```

#### 2. Add SSH Key to GitHub

1. Copy your public key:
   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```
2. Go to GitHub: **Settings** → **SSH and GPG keys** → **New SSH key**
3. Select **Signing Key** as the key type
4. Paste your public key

#### 3. Configure Git for SSH Signing

```bash
# Tell Git to use SSH for signing
git config --global gpg.format ssh

# Set your SSH key for signing
git config --global user.signingkey ~/.ssh/id_ed25519.pub

# Enable automatic commit signing
git config --global commit.gpgsign true
```

#### 4. Make a Signed Commit

```bash
git commit -m "feat: add new feature"
```

## Verification

### Check if a Commit is Signed

```bash
# Verify the last commit
git verify-commit HEAD

# Show signature information
git log --show-signature -1
```

### View Signature Status on GitHub

- Signed commits show a **Verified** badge on GitHub
- Unsigned commits show **Unverified** or no badge

## Troubleshooting

### GPG: signing failed: Inappropriate ioctl for device

```bash
export GPG_TTY=$(tty)
```

Add this to your `~/.bashrc` or `~/.zshrc`:
```bash
echo 'export GPG_TTY=$(tty)' >> ~/.bashrc
source ~/.bashrc
```

### GPG: signing failed: No secret key

Your key might have expired or been deleted. List your keys:
```bash
gpg --list-secret-keys --keyid-format=long
```

If no keys are listed, generate a new one (see step 1).

### Commits Not Showing as Verified on GitHub

1. **Email mismatch**: Ensure your Git email matches your GitHub email:
   ```bash
   git config --global user.email "your.email@example.com"
   ```

2. **Key not added to GitHub**: Make sure you've added your public key to GitHub

3. **Key expired**: Check if your key has expired:
   ```bash
   gpg --list-keys
   ```

### Sign Previous Commits

To sign previous commits (use with caution - rewrites history):

```bash
# Sign the last commit
git commit --amend --no-edit -S

# Sign multiple commits (interactive rebase)
git rebase -i HEAD~3 --exec "git commit --amend --no-edit -S"
```

**Warning**: This changes commit hashes. Only do this before pushing or on your own branches.

## Pipeline Behavior

### What Gets Checked

- **Pull Requests**: All new commits in the PR
- **Push to main**: All commits in the push
- **Other events**: The HEAD commit

### When Pipeline Fails

If any commit is unsigned, the pipeline will:
1. ❌ Fail the `verify-commit-signatures` job
2. 🛑 Block the `build` job from running
3. 📝 Display which commits are unsigned
4. 📚 Show instructions for signing commits

### Example Failure Output

```
❌ VERIFICATION FAILED!

The following commits are not signed:
  - a1b2c3d
  - e4f5g6h

📚 How to sign commits:
[Instructions displayed in pipeline logs]
```

## Best Practices

1. **Always sign commits**: Enable automatic signing with `git config --global commit.gpgsign true`
2. **Use strong keys**: 4096-bit RSA or Ed25519 keys
3. **Set expiration**: Keys should expire after 1-2 years for security
4. **Backup your keys**: Store your private key securely
5. **Rotate keys**: Generate new keys before old ones expire
6. **Verify before pushing**: Check commits are signed with `git log --show-signature`

## Additional Resources

- [GitHub: Managing commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification)
- [GitHub: Signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
- [GitHub: Adding a GPG key](https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account)
- [Git: Signing Your Work](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)

## Support

If you encounter issues with commit signing:
1. Check the troubleshooting section above
2. Review the GitHub documentation
3. Contact the repository maintainers