# ft_ssl - Technical overview

## 1. Objective

ft_ssl is a C implementation of a small set of cryptographic primitives inspired by OpenSSL. The project focuses on educational value and on a clean, architecture-oriented implementation of legacy primitives: hashing, Base64 conversion, and symmetric encryption.

The purpose is not to replace OpenSSL in production environments. The implementation is intentionally limited and follows a teaching-oriented approach rather than matching the breadth, robustness, and compatibility guarantees of the official OpenSSL toolchain.

The program does, however, emulate legacy OpenSSL-compatible behavior when used with the appropriate flags. For example, the DES-based encryption flow can be compared with the following OpenSSL invocation:

```bash
openssl enc -des-ecb -provider legacy
```

This indicates that the project is targeted at historical, legacy cryptographic behavior, not modern secure defaults.

## 2. Scope of the implementation

The project includes:

- MD5, SHA-224, SHA-256, SHA-512
- Base64 encoding and decoding
- DES and Triple DES block ciphers
- Various block cipher mode of operation: CBC, ECB, PCBC, CFB and OFB
- PBKDF-based key derivation for password-driven encryption flows
- CLI and interactive execution modes
- handling of input from files or strings

## 3. Legacy compatibility and limitations

This project intentionally reimplements older cryptographic primitives that are considered obsolete in modern security practice.

- DES has been largely superseded by AES and should not be considered a modern recommendation.
- The password-based derivation implemented here is PBKDF1 rather than PBKDF2.
- The utility is designed around compatibility with older OpenSSL behavior and legacy option semantics, not modern security guidance.

In other words, the value of the project is architectural and didactic: it demonstrates how block ciphers, hash functions, key schedules, and derivation functions can be implemented and assembled into a coherent command-line tool.

## 4. Build

From the project root:

```bash
make
./ft_ssl --help
```

## 5. Typical usage

### Hashing

```bash
./ft_ssl md5 file.txt
./ft_ssl sha256 "hello world"
./ft_ssl sha512 -s "hello world"
```

Common digest options:

- `-p`, `--echo`
- `-q`, `--quiet`
- `-r`, `--reverse`
- `-s`, `--string`

### Base64

```bash
./ft_ssl base64 -e -i input.txt -o output.txt
./ft_ssl base64 -d -i encoded.txt -o decoded.txt
```

### Encryption

```bash
./ft_ssl des -e -k 0011223344556677 -i plain.txt -o cipher.txt
./ft_ssl des3 -d -k 00112233445566778899AABB -v 0102030405060708 -i cipher.txt -o plain.txt
```

Supported cipher families include:

- `des`
- `des-ecb`
- `des-cbc`
- `des-pcbc`
- `des-cfb`
- `des-ofb`
- `des3`
- `des3-ecb`
- `des3-cbc`
- `des3-pcbc`
- `des3-cfb`
- `des3-ofb`

## 6. Architecture and execution model

The program follows a compact but structured execution flow:

1. Entry point: the main dispatcher resolves the command name and selects the correct handler.
2. Argument parsing: each algorithm owns a dedicated parser that validates flags and extracts parameters.
3. Data preparation: input is read from a file or a string, and optional Base64 processing is applied when required.
4. Cryptographic processing: hashing, block cipher logic, or PBKDF derivation operates on the prepared buffer.
5. Output: the result is emitted to stdout or written to a file, depending on the selected mode.

This gives the project a clear separation of responsibilities while keeping the overall implementation compact and readable.

## 7. Notes on the cryptographic design

The implementation is intentionally explicit: it demonstrates core cryptographic building blocks rather than abstracting them behind a heavy framework. This is visible in the separation between:

- algorithm-specific logic,
- generic I/O management,
- argument validation,
- and shared helpers for bit manipulation and permutation logic.

The use of a shared I/O context allows the same file-oriented pipeline to be reused across different primitives, including Base64-wrapped encryption flows. Similarly, the PBKDF helper centralizes the hash selection and derived-key generation, making the password-based encryption path easier to reason about and test.

## 8. Sources

### Digest algorithms

https://en.wikipedia.org/wiki/MD5
https://en.wikipedia.org/wiki/SHA-2

### Key derivation and PBKDF1

https://www.rfc-editor.org/info/rfc2898/

### DES encryption

https://en.wikipedia.org/wiki/Data_Encryption_Standard

### DES-3 encryption

https://en.wikipedia.org/wiki/Triple_DES

### Encryption mode of operations

https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation