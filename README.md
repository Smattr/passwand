# passwand

A password manager for Linux.

This tool is designed for encrypted storage and retrieval of entries consisting of a space, key and
value. These fields are encrypted using a master passphrase which is required to retrieve any entry.
The interface is fairly unpolished, but the underlying implementation is intended to preserve strong
security properties on data both at-rest and in-memory.

Note that you can use this tool to store data that are not passwords, but password storage is the
most common use case. While this code may run on platforms other than Linux, I would recommend using
[1Password](https://agilebits.com/onepassword) instead where possible for the reasons discussed
below.

## Disclaimer

You are free to use this code for any purpose you choose. I consider it to be in the public domain.
However, be aware that it comes with absolutely no licence or warranty. It is published here because
I don't believe in security by obscurity, but I am not in any way attesting as to the security of a
password stored with this tool. The attack model I have in mind and have tried to defend against is
a malicious party who has your data file and all code in this repository. I have tried to follow
sensible practices where applicable, but, as I mention below, I am not a cryptographer.

If you find any bugs (security related or otherwise) in this code or simply have questions, please
email me or open a new ticket.

## Cryptography

One of the most foolish things you can do is implement your own cryptography protocol when you are
not a crypto expert. I am not a crypto expert. With this in mind from the outset, the backend of this
tool was modeled after 1Password's storage format.

Agile Bits, the makers of 1Password, are very clever folk and have gone to significant effort to
ensure the security of its on-disk data format. If 1Password were available for Linux, Passwand
would probably not exist.

The design of 1Password's key chain and `opdata` format are documented in the following:

  * http://learn2.agilebits.com/1Password4/Security/keychain-design.html
  * https://support.1password.com/agile-keychain-design/
  * https://support.1password.com/opvault-design/
  * https://support.1password.com/defense-against-crackers/

The motivation for various places where we follow 1Password or deviate from their design are
documented below (partly to inform you, partly to remind myself):

  * Most crypto tools, including 1Password, use a [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator)
    for generating random data. Instead, we just **read directly from /dev/random** because we have
    no need for low latency and there are flaws with most of the widely available CSPRNGs.
  * Instead of using a PBKDF2-HMAC-SHA512 as a
    [KDF](https://en.wikipedia.org/wiki/Key_derivation_function), we use **Scrypt**. Agile Bits note
    that they would probably also do this (as it has better resistance against GPU-hosted attacks)
    except for it not being widely available outside of Linux/BSD.
  * 1Password generates a single 512-bit key which it then chops in half to get a 256-bit encryption
    key and a 256-bit HMAC key. Instead we just **run our KDF twice with different salts**
    to generate one key for encryption and one key for HMAC. This is possible because our KDF,
    Scrypt, does not have a fixed width unlike theirs.
  * Like 1Password, we **prepend padding** instead of appending it. Agile Bits argument for this is
    that it acts as an extra initialisation vector.
  * We use **random padding bytes** and so does 1Password, though Agile Bits suggest deterministic
    padding based on an [IETF draft](https://www.ietf.org/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-01.txt)
    may be simpler with no loss of security. I do not follow their argument for why this does not
    weaken security, so have stuck with random padding.
  * Our packed data format begins with `oprime01`, while 1Password's begins with `opdata01`. This
    value is arbitrary and there was no rationale for using the same format marker as 1Password when
    our format is not the same.
  * 1Password keeps some information unencrypted on disk and other information unencrypted in memory
    for significant amounts of time. Again, because we have no latency requirements, we just encrypt
    all identifying information on disk and only maintain decrypted information in memory for the
    minimum necessary time. In particular, Passwand entries are never in an "unlocked" state as they
    can be in 1Password.
  * 1Password uses a hierarchy of derived keys, such that any leaf derived key is only ever used
    for encryption within a single item. Their motivation is to defend against the same key being
    used for large amounts of data, giving an attacker a lot of cipher text to play with. Because,
    unlike 1Password, we do not allow the storing of attachments, this is not a concern for us and
    we use **a single derived key** for encryption.
  * We use **AES in CTR mode**, while 1Password uses CBC mode. Agile Bits note their preference for
    CTR mode, but that it is not as widely available.
  * We use **AES256 encryption**. 1Password switched from 128-bit AES encryption to 256-bit, though they themselves
    acknowledge that it provides no practical increase in security. The only non-PR motivation they
    have for switching is defending against brute force attacks by quantum computers. The time taken
    to brute force a 128-bit key on a quantum computer is proportional to 2^64^, instead of 2^128^,
    making this feasible. Brute forcing a 256-bit key on a quantum computer is supposedly
    proportional to 2^128^. A brute force attack proportional to 2^128^ (classical computer on a
    128-bit key or quantum computer on a 256-bit key) is currently considered infeasible. The NSA
    also uses this motivation for their use of 256-bit keys.
    [More](https://blog.agilebits.com/2013/03/09/guess-why-were-moving-to-256-bit-aes-keys/).
