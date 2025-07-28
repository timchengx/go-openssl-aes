# go-openssl-aes
A openssl aes-256-cbc with PBKDF2 compatible encryptor/decryptor


# How to use
```
Encrypt/Decrypt file by openssl aes-256-cbc with pbkdf2 key derivation

Usage:
  go-openssl-aes [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  decrypt     Decrypt file encrypted by program or OpenSSL AES algorithm
  encrypt     Encrypt file encrypted by program or OpenSSL AES algorithm
  help        Help about any command

Flags:
  -h, --help            help for go-openssl-aes
  -i, --iter string     PBKDF2 key derivation iteration - OpenSSL default 10000 (default "200000")
  -o, --output string   output file path (default "./output")

Use "go-openssl-aes [command] --help" for more information about a command.
```

# Concept used
Project aims to compatiable with using openssl aes-256-cbc with pbkdf2 key derivation encrypt/decrypt. With following concepts:

## File format
OpenSSL defines following file format:
```
+----------------------+-----------------+----------------------------------+
| "Salted__" (8 bytes) | Salt (8 bytes)  |      Ciphertext (n bytes)        |
+----------------------+-----------------+----------------------------------+
First 8 bytes act as magic string, indicates encryption file has Salt data
```

## Salt
8 bytes random salt generated for increase randomness. Used in PBKDF2 key derivation.

## PBKDF2 Key derivation
Generate necessary key and initial vector (IV) for following AES CBC operation.
Programs chooses HMAC-SHA256 as PRF with default iteration count of 200000. (OpenSSL default uses 10000). Generate 48 bytes in one time, split into key and IV.

* First 32 bytes as Key
* Last 16 bytes as IV

## aes-256-cbc
Standard AES 256 bit encryption with cipher block chaining mode.

## pkcs#7 padding
AES operation requires data to be a multiple of the block size(16 bytes).
This is achieved by PKCS#7 padding, will have 2 types of padding:

* If last data is contains full 16 bytes, a whole block of padding is added with 0x10 (16).
* If last data is not full 16 bytes, padding will be added to make it full 16 bytes. Content of remaining bytes is filled with padding size. E.g. If last data is 12 bytes, padding will be added with 4 bytes, and each of remaining byte is filled with 0x04 (4).

# References
http://justsolve.archiveteam.org/wiki/OpenSSL_salted_format

https://en.wikipedia.org/wiki/Salt_(cryptography)

https://en.wikipedia.org/wiki/PBKDF2

https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)

https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
