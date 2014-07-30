# passwand

A password manager for Linux.

This tool is designed for encrypted storage and retrieval of entries consisting
of a namespace, key and value. These fields are encrypted using a master
password which is required to retrieve any entry. The interface is fairly
unpolished, but the underlying implementation is intended to preserve strong
security properties on the stored data.

Note that you can use this tool to store data that are not passwords, but
password storage is the most common use case. While this code should run on
platforms other than Linux, I would recommend using
[1Password](https://agilebits.com/onepassword) instead where possible for the
reasons discussed below.

## Disclaimer

You are free to use this code for any purpose you choose. I consider it to be
in the public domain. However, be aware that it comes
with absolutely no licence or warranty. It is published here because I don't
believe in security by obscurity, but I am not in any way attesting as to the
security of a password stored with this tool. The attack model I have in mind
and have tried to defend against is a malicious party who has your data file
and all code in this repository. I have tried to follow sensible practices
where applicable, but, as I mention below, I am not a cryptographer.

If you find any bugs (security related or otherwise) in this code or simply
have questions, please email me or open a new ticket.

## A note on encryption

One of the most foolish things you can do is implement your own cryptography
protocol when you are not a crypto expert. I am not a crypto expert. With
this in mind from the outset, the backend of this tool was designed to mimic
1Password's storage format quite closely.

Agile Bits, the makers of 1Password, are very clever folk and have gone to
significant effort to ensure the security of its on-disk data format. If
1Password were available for Linux, this tool here would not exist.

The algorithm used here differs from 1Password in a few significant ways,
including the following:

* The use of scrypt as a Key Derivation Function (KDF) instead of PBKDF2. Agile
  Bits
  [mention they would consider scrypt](http://learn2.agilebits.com/1Password4/Security/keychain-design.html),
  but for its absence on some
  platforms. On Linux, we don't have such qualms.
* Encryption uses AES in counter mode instead of Cipher Block Chaining (CBC)
  mode. Again,
  [this is recommended by Agile Bits](http://learn2.agilebits.com/1Password4/Security/keychain-design.html),
  but held back by availability
  issues.
* Less plain text on disk. 1Password stores some fields unencrypted so they can
  be looked up or categorised without the master password available. I had no
  need for such functionality, so simply chose to encrypt all fields.

1Password also performs some optimisations, including keeping limited plain
text data resident in memory to avoid the overhead of re-decrypting. I chose to
live with high latency on password retrieval in exchange for minimising the
time plain text is in memory for. You can balance the speed at which a password
can be retrieved against the encryption strength using the `--work-factor`
parameter.

In the discussion of potential 1Password security improvements, Agile Bits also
mention an
[IETF proposal](http://www.ietf.org/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-01.txt)
concerning alternate padding of the input data. In counter
mode, as used in this tool, input alignment -- and hence, padding -- is not
required. I have retained
padding anyway as I believe it provides extra security by acting as an extra
salt, as mentioned by Agile Bits. Instead of adopting the deterministic padding
in the IETF's proposal, I have stuck with 1Password's original padding scheme. I
willingly confess this is because I do not understand how the proposed scheme
improves the
security of the algorithm. Agile Bits are correct that the padding scheme is
simpler, but it appears to weaken the security properties to me. Nevertheless,
I suspect they know something I do not here.
