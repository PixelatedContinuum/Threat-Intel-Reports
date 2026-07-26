---
title: PGP Key
nav_title: PGP Key
layout: page
permalink: /pgp/
---

<div class="hl-page-header" style="--ph-accent: #58a6ff;">
  <div class="hl-page-header__label">Secure Contact</div>
  <div class="hl-page-header__title">PGP Public Key</div>
  <div class="hl-page-header__desc">For sending sensitive material to The Hunter's Ledger, including victim-identifying detail, credentials, and pre-publication findings.</div>
</div>

## Fingerprint

```
228F D729 F9C5 45CE F381  64A8 9FA0 CE30 5AF9 1383
```

Key ID `9FA0CE305AF91383`, RSA 4096, created 26 July 2026, valid to 26 July 2027.
Identity: Joseph Harrison &lt;the.hunters.ledger@gmail.com&gt;.

**Verify the fingerprint before you use the key.** Compare what you see here against a second,
independent source rather than trusting this page alone. Checking a key against the same channel it
arrived on proves nothing, and out-of-band verification is what defeats a substituted key.

## When to use it

Use it for anything you would not put in plaintext email. Compromised-account identifiers,
credentials, victim-identifying detail, malware samples, and any pre-publication finding you want
handled in confidence all qualify.

National CERTs, incident response teams, and affected organizations are welcome to open an encrypted
channel at any time, whether or not an exchange is already under way. If your team publishes its own
key, send it, and anything going back the other way will be encrypted to it.

Reports, detection rules, and indicator feeds published here are open by design and need no
encryption. This key exists for the material that sits behind them.

## Download

[hunters-ledger-pubkey.asc](/assets/pgp/hunters-ledger-pubkey.asc)

The same key is referenced as the `Encryption` field of
[/.well-known/security.txt](/.well-known/security.txt), per RFC 9116.

Import it:

```
gpg --import hunters-ledger-pubkey.asc
```

Or fetch and import in one step:

```
curl -s https://the-hunters-ledger.com/assets/pgp/hunters-ledger-pubkey.asc | gpg --import
```

## Public key block

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
AFq79SS+Z1U+B8gmjFr53vD9nlPDxgJ4PQ==
=eXQO
-----END PGP PUBLIC KEY BLOCK-----
```
