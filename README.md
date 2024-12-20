# pwds

Command line interface for managing passwords.

## Features

* Easy to use CLI interface
* Passwords are encrypted with AES 256-bit keys.
* Encryption keys are stored in NSS database.
* Master key rotation.
* Remote backup

## Usage

```bash
# Create vault
pwds vault create --name "main"

# Select vault
pwds vault select --name "main"

# Create a secret
pwds secret create --name "foo"

# Retreive a secret
pwds secret get --name "foo"

# List secrets (only the names)
pwds secret list

# Update a secret
pwds secret set --name "foo"

# Delete a secret
pwds secret delete --name "foo"

# Persist vault password
pwds vault persist --pwfile "~/.pwds/pwfile"  # The password is base64 encoded
pwds secret get -n "foo" -p "~/.pwds/pwfile"  # No password prompt; nice for scripting!

# Rotate encryption key (re-encrypts secrets automatically)
pwds vault rotate

# Sync secrets with a remote server
pwds config sync-url --value "https://pwds.byjonah.net"
pwds vault sync
```

## Dependencies

* nss-softokn
* curl
* botan
* sqlite3

### Developer's Note

This repository is not well set up for an easy build. The meson build file
could be greatly improved and is largely configured for my system in
particular.

I developed this on Linux and wrote the PKCS11 headers to work on UNIX systems.
If you are on Windows, you will need to modify `include/pkcs11/cryptoki.h` to
include macros for Windows.

I also wrote the `include/args` library and it has some quirks between Linux
and macOS, so there's almost certainly some issues on Windows too.

This project was designed to work with NSS "vaults", but could be extended to
use various PKCS11 libraries for personal use with smart cards or smart sticks.
In an enterprise setting, an HSM could be used.

## Motivation

My day job focuses very heavily on cryptography, specifically working with
PKCS11 modules. In my free time I will often work on side projects that are
in some way related to this sector. It's known that software implementations of
PKCS11 are not very secure, but in terms of local password storage, it is
probably the most approachable solution while still maintaining some base level
of security (ie, not storing passwords in plaintext, simulating secure storage
of encryption keys, etc).

I also have to maintain and keep track of several passwords at work that I would
prefer to not have in a plain text file, but I also don't want to import them
into my Bitwarden as those credentials would then be held off-site which is
very undesirable. Taking this into account, I decided it would be a fun
challenge to write my own password manager solution. So far it has proven to
be quite useful!

Regarding the remote backup/sync feature: I wrote this part as a personal
challenge. At work I have no use for this, but if I use this program in my
personal life, I could keep various API keys and passwords stored securely in
the cloud as well as on my personal devices and keep them in sync with each
other. At present, the only feature sync has is to upload the secrets I have
locally that have been created or updated after a certain point in time (ideally
the time of the last sync). Ways to flesh this out:

* Publish server side code (currently WIP)
* Locally maintain last sync time and include in initial GET request.
* Retreive any changes on the server since my last sync
* Download those changes and merge with local database
* Display and manage sync conflicts

## Architecture / Design

pwds manages two databases:

* sqlite => secrets and master key metadata (keys.db)
* NSS => "secure" key storage (nss/)

When a vault is created, the below flow happens:

1. NSS and sqlite databases are created and initialized. The vault password is
the same as the NSS password and is what's sent to NSS via PKCS11.
2. A master key (AES-256) is generated in NSS. The metadata (alias, key type) are
saved in the sqlite database.
3. A global configuration TOML is generated if it doesn't exist. The vault details
are saved to this configuration file.

When a secret is created:

1. pwds gets the master key metadata from the sqlite database.
2. Using the master key present in the NSS database, the provided secret value
is encrypted.
3. The encrypted data and the initialization vector (iv) for the encryption
operation are saved in the sqlite database (along with the secret name and
some timestamps).

To retreive a secret:

1. The secret metadata is looked up in the sqlite database.
2. If found, the master key is also looked up.
3. Like the encryption flow, the encrypted data is given to NSS via PKCS11
and decrypted with the same master key.
4. Decrypted data is returned.

When secrets are rotated:

1. A new master key is generated in NSS. The metadata is saved in sqlite.
2. Going through the sqlite database, each secret undergoes the following:
  * Secret is decrypted with the original master key.
  * Secret is re-encrypted with the new master key.
  * Details are saved in the database
3. After all secrets have been rotated, the original master key is deleted from
NSS and sqlite.
4. The new master key is saved in sqlite.

### Remote Upload

To upload secrets to a remote server:

1. Retreive trust details from the remote server
  * Trust details include a PEM encoded X.509 certificate (RSA) and the trust chain
    for that certificate. If pwds receives a certificate and trust chain that are
    invalid, it will warn the user.
2. Extract the RSA public key from the given certificate. Import the RSA key into
NSS via PKCS11.
3. For each secret that is locally determined to be uploaded (based on sync time
provided by the server):
  * Decrypt using master key
  * Re-encrypt using the imported public key
4. Send POST request to remote server including secrets encrypted with public key
from certificate.
5. The NSS database will automatically remove the public key from its database.

On the server side, the private key will be used to decrypt the secrets and then
the secrets will be handled however the server decides to handle them.
