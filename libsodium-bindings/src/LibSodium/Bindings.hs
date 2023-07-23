-- |
--
-- Module: LibSodium.Bindings
-- Description: Index of the libsodium-bindings package
-- Copyright: (C) Hécate Moonlight 2023
-- License: BSD-3-Clause
-- Maintainer: The Haskell Cryptography Group
-- Stability: Stable
-- Portability: GHC only
--
-- You will find below a list of the cryptographic bindings exposed:
--
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  |           Purpose           | Description                                                          | Algorithms                            | Module                                                  |
-- +==+=============================+======================================================================+=======================================+=========================================================+
-- |  | __Secret-key Cryptography__ |                                                                      |                                       |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Authenticated Encryption    | Encrypt a message and compute an authentication                      | Encryption: XSalsa20 stream cipher;   | [SecretBox]("LibSodium.Bindings.Secretbox")             |
-- |  |                             | tag to make sure the message hasn't been tampered with.              | Authentication: Poly1305 MAC          |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Encrypted Streams           | Encrypt a sequence of messages, or a single message split            | Initialisation: XChaCha20;            | [SecretStream]("LibSodium.Bindings.SecretStream")       |
-- |  |                             | into an arbitrary number of chunks, using a secret key.              | Encryption: ChaCha20Poly1305-IETF     |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Authentication              | Compute an authentication tag for a message and a secret key,        | Authentication: HMAC-SHA512-256       | [CryptoAuth]("LibSodium.Bindings.CryptoAuth")           |
-- |  |                             | and verify that a given tag is valid for a given message and a key.  |                                       |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | __Public-key Cryptography__ |                                                                      |                                       |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Authenticated Encryption    | Encrypt a confidential message with the recipient's public key,      | Key exchange: X25519;                 | [CryptoBox]("LibSodium.Bindings.CryptoBox")             |
-- |  |                             | who can then decrypt it with their secret key.                       | Encryption: XSalsa20;                 |                                                         |
-- |  |                             |                                                                      | Authentication: Poly1305              |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Public-key Signatures       | Sign messages with a secret key, and distribute a public key,        | Single-part signature: Ed25519;       | [CryptoSign]("LibSodium.Bindings.CryptoSign")           |
-- |  |                             | which anybody can use to verify that the signature appended          | Multi-part signature: Ed25519ph       |                                                         |
-- |  |                             | to a message was issued by the creator of the public key.            |                                       |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Sealed Boxes                | Anonymously send messages to a recipient given their public key.     | Key Exchange: X25519;                 | [SealedBoxes]("LibSodium.Bindings.SealedBoxes")         |
-- |  |                             |                                                                      | Encryption: XSalsa20-Poly1305         |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | __Hashing__                 |                                                                      |                                       |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Generic Hashing             | Computes a fixed-length fingerprint for an arbitrarily long message. | Hashing: BLAKE2b                      | [GenericHashing]("LibSodium.Bindings.GenericHashing")   |
-- |  |                             | Use this for file integrity checking and create unique identifiers   |                                       |                                                         |
-- |  |                             | to index arbitrarily long data.                                      |                                       |                                                         |
-- |  |                             | Do not use this API to hash passwords!                               |                                       |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Password Hashing            | Hash passwords with high control on the computation parameters.      | Hashing: Argon2id v1.3                | [PasswordHashing]("LibSodium.Bindings.PasswordHashing") |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Short-input Hashing         | Produce short hashes for your data, suitable to build Hash tables,   | Hashing: SipHash-2-4                  | [ShortHashing]("LibSodium.Bindings.ShortHashing")       |
-- |  |                             | probabilistic data structures or perform integrity checking in       |                                       |                                                         |
-- |  |                             | interactive protocols.                                               |                                       |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | __Cryptographic Keys__      |                                                                      |                                       |                                                         |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Key Derivation              | Derive secret keys from a single high-entropy key.                   | Key derivation: BLAKE2B               | [KeyDerivation]("LibSodium.Bindings.KeyDerivation")     |
-- |  +-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Key Exchange                | Securely compute a set of shared keys using your                     | Key generation: BLAKE2B-512           | [KeyExchange]("LibSodium.Bindings.KeyExchange")         |
-- |  |                             | peer's public key and your own secret key.                           |                                       |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | __Other constructs__        |                                                                      |                                       |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | SHA-2                       | Provide compatibility with existing applications for                 | SHA-256 and SHA-512                   | [SHA2]("LibSodium.Bindings.SHA2")                       |
-- |  |                             | SHA-256 and SHA-512. You should prioritise GenericHashing            |                                       |                                                         |
-- |  |                             | and PasswordHashing for new developmentinstead.                      |                                       |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | AEAD                        | Encrypt a message with a key and a nonce to keep it confidential,    | Encryption: XChaCha20 stream cipher;  | [AEAD]("LibSodium.Bindings.AEAD")                       |
-- |  |                             | compute an authentication tag, and store optional, non-confidential  | Authentication: Poly1305 MAC          |                                                         |
-- |  |                             | data.                                                                |                                       |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | XChaCha20                   | Implementation of the XChaCha20 stream cipher                        | XChaCha20 stream cipher               | [XChaCha20]("LibSodium.Bindings.XChaCha20")             |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
-- |  | Scrypt                      | Unless you have specific reasons to use scrypt, you                  | scrypt password hashing function      | [Scrypt]("LibSodium.Bindings.Scrypt")                   |
-- |  |                             | should instead consider the PasswordHashing module!                  |                                       |                                                         |
-- +--+-----------------------------+----------------------------------------------------------------------+---------------------------------------+---------------------------------------------------------+
module LibSodium.Bindings where
