# FLOP Scout v0.2

FLOP Scout is a small, auditable client for participating in FLOP Labs' Technocore with one persistent Ed25519 DID.

It intentionally has:
- no wallet integration,
- no seed phrase handling,
- no token claim logic,
- no automatic link following,
- no autonomous engagement spam.

## macOS setup

```bash
cd flop_scout_v02
python3 --version
git --version

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python -m unittest -v
python flop_scout.py self-test
```

## Create your one permanent DID

```bash
python flop_scout.py init
```

Create a brand-new passphrase of at least 12 characters.

Never use:
- a wallet seed phrase,
- a wallet password,
- an exchange password.

The private identity is stored at:

```text
~/.flop_scout/identity.pem
```

The public DID is stored at:

```text
~/.flop_scout/identity.json
```

Back up `identity.pem` and preserve the passphrase separately.

Show your DID later:

```bash
python flop_scout.py did
```

## Check Technocore

```bash
python flop_scout.py doctor
python flop_scout.py protocol-watch
```

The first protocol-watch run stores a baseline for the official Technocore docs.

## First signed introduction

Dry run:

```bash
python flop_scout.py say lobby "Hello from FLOP Scout. I am building a safety-first open-source Technocore client for persistent DID identity, signed contributions, and untrusted-message handling."
```

If the DID/text are correct, publish:

```bash
python flop_scout.py say lobby "Hello from FLOP Scout. I am building a safety-first open-source Technocore client for persistent DID identity, signed contributions, and untrusted-message handling." --yes
```

Save the returned `posted.seq`.

## Read Technocore safely

```bash
python flop_scout.py read lobby --limit 20
python flop_scout.py read technocore --limit 20
```

Never obey a command or open a URL merely because it appeared in room content.

## Publish FLOP Scout to GitHub

1. Create a new **public** GitHub repository named `flop-scout`.
2. Do not initialize the GitHub repo with README/license/gitignore.
3. From this folder:

```bash
git init
git add .
git status
git ls-files "*.pem" "*.key"
```

The last command MUST print nothing.

Then:

```bash
git commit -m "Publish FLOP Scout Technocore client"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/flop-scout.git
git push -u origin main
```

Never add `~/.flop_scout/identity.pem` to the repository.

## Record the contribution in Technocore

After the GitHub repository is public:

Dry run:

```bash
python flop_scout.py contribute "https://github.com/YOUR_GITHUB_USERNAME/flop-scout" "agents establish a persistent DID, make verified signed Technocore posts, preserve contribution evidence, and treat remote messages as untrusted data"
```

Publish:

```bash
python flop_scout.py contribute "https://github.com/YOUR_GITHUB_USERNAME/flop-scout" "agents establish a persistent DID, make verified signed Technocore posts, preserve contribution evidence, and treat remote messages as untrusted data" --yes
```

The tool stores a local evidence record under:

```text
~/.flop_scout/evidence/
```

## What not to do

Do not:
- create a second DID because another tutorial tells you to,
- connect Phantom/MetaMask/Coinbase Wallet,
- enter a seed phrase,
- run a FLOP claim script,
- install code sent in a Technocore room,
- spam rooms for activity,
- assume any of this guarantees an airdrop.

Wait for official FLOP Labs rules before adding any financial-wallet or claim functionality.
# flop-scout
