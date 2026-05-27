## Summary
This codebase is a C implementation of the zpicotls TLS stack. The public API in `include/zpicotls.h` defines the TLS context, buffer, crypto algorithm interfaces, handshake properties, and utility helpers, while the core protocol logic lives in `lib/picotls.c`. Multiple crypto backends are supported via pluggable algorithm objects (OpenSSL, mbedTLS/PSA, a minimal in-tree minicrypto based on Cifra and micro-ecc, Windows BCrypt, and x86 SIMD fusion). Additional modules provide HPKE, ECH helpers, certificate compression, QUIC-LB transforms, FFX format-preserving encryption, ASN.1/PEM parsing, and logging. Tests and tooling in `t/` exercise the core protocol, backends, and feature modules, with vendored crypto implementations under `deps/`. Research conducted on January 1, 2026.

## Coding style and conventions
- 4-space indentation with K&R/LLVM-style braces on the same line as declarations (e.g., function definitions in `lib/*.c`).
- Public API functions and types use the `ptls_` prefix; struct tags use `st_` (e.g., `struct st_ptls_context_t`) with `typedef` aliases (e.g., `ptls_context_t`) in `include/zpicotls.h`.
- Constants and feature flags are uppercase with `PTLS_` prefixes; compile-time configuration uses `#if`/`#ifdef` guards across platforms.
- File-scope helpers are `static` and often `static inline` in headers for performance (e.g., `lib/chacha20poly1305.h`).
- Vendor libraries keep their native prefixes (`cf_` for Cifra, `uECC_` for micro-ecc), while zpicotls backends wrap them with `ptls_*` objects.

## Detailed Findings

### Public API and core types (include/zpicotls.h)
- Defines the main TLS context, handshake property structures, and logging types used throughout the codebase (`include/zpicotls.h:867`, `include/zpicotls.h:1091`, `include/zpicotls.h:1544`).
- Defines the crypto abstraction interfaces for key exchange, cipher, AEAD, and cipher suites (`include/zpicotls.h:384`, `include/zpicotls.h:463`, `include/zpicotls.h:518`, `include/zpicotls.h:643`).
- Provides buffer and iovec types used for message and record processing (`include/zpicotls.h:343`, `include/zpicotls.h:351`).

### Backend API headers (include/zpicotls/*.h)
- ASN.1 validation and parsing API used by PEM/key helpers (`include/zpicotls/asn1.h:42`).
- Certificate compression API with brotli-based decompressor and compressed certificate emitter (`include/zpicotls/certificate_compression.h:43`, `include/zpicotls/certificate_compression.h:48`).
- FFX format-preserving encryption context and setup helpers (`include/zpicotls/ffx.h:78`, `include/zpicotls/ffx.h:129`, `include/zpicotls/ffx.h:136`).
- Fusion AES-ECB/AES-GCM and QUIC-LB interfaces, plus CPU capability check (`include/zpicotls/fusion.h:41`, `include/zpicotls/fusion.h:81`, `include/zpicotls/fusion.h:111`).
- mbedTLS/PSA backend algorithm declarations and key loading hooks (`include/zpicotls/mbedtls.h:34`, `include/zpicotls/mbedtls.h:61`, `include/zpicotls/mbedtls.h:63`).
- Minicrypto backend declarations for algorithms, key exchange, and PEM key loading (`include/zpicotls/minicrypto.h:35`, `include/zpicotls/minicrypto.h:40`, `include/zpicotls/minicrypto.h:45`, `include/zpicotls/minicrypto.h:73`).
- OpenSSL backend declarations for algorithms, signature schemes, verification, ticket encryption, and HPKE (`include/zpicotls/openssl.h:108`, `include/zpicotls/openssl.h:122`, `include/zpicotls/openssl.h:159`).
- PEM/base64 utilities for certificates and keys (`include/zpicotls/pembase64.h:35`, `include/zpicotls/pembase64.h:42`).
- Windows BCrypt backend declarations (`include/zpicotls/ptlsbcrypt.h:34`).

### Core TLS engine (lib/picotls.c)
- Buffer growth and encoding/decoding helpers used across handshake and record processing (`lib/picotls.c:581`, `lib/picotls.c:926`).
- Certificate message construction used by handshake and compression helpers (`lib/picotls.c:3129`).
- TLS object lifecycle and context accessors (`lib/picotls.c:5179`, `lib/picotls.c:5196`, `lib/picotls.c:5470`).
- Handshake driver and record send/receive paths (`lib/picotls.c:6033`, `lib/picotls.c:6096`, `lib/picotls.c:6156`).
- Key update and secret export helpers (`lib/picotls.c:6179`, `lib/picotls.c:6214`).
- HKDF/HMAC utilities and AEAD/cipher construction (`lib/picotls.c:6337`, `lib/picotls.c:6351`, `lib/picotls.c:6449`, `lib/picotls.c:6487`).
- ECH config encoding, address parsing, and logging plumbing (`lib/picotls.c:6708`, `lib/picotls.c:6693`, `lib/picotls.c:6926`).

### Utility and feature modules (lib/*.c, lib/*.h)
- ASN.1 parsing/validation used by minicrypto key loader (`lib/asn1.c:284`).
- Base64 + PEM parsing and certificate loading (`lib/pembase64.c:299`).
- Minicrypto PKCS#8/EC private key decoding (`lib/minicrypto-pem.c:324`).
- Brotli-based certificate compression and decompression integration (`lib/certificate_compression.c:122`).
- HPKE labeled extract/expand, DH encapsulation, and setup (`lib/hpke.c:224`, `lib/hpke.c:248`).
- FFX format-preserving cipher context and transform (`lib/ffx.c:32`, `lib/ffx.c:104`).
- QUIC-LB transformation helper shared by backends (`lib/quiclb-impl.h:108`).
- Common ChaCha20-Poly1305 AEAD glue used by different backends (`lib/chacha20poly1305.h:166`).
- AEGIS AEAD context implementation used by minicrypto (`lib/libaegis.h:35`, `lib/cifra/libaegis.c:26`).

### Crypto backends (lib/openssl.c, lib/mbedtls.c, lib/mbedtls_sign.c, lib/fusion.c, lib/ptlsbcrypt.c, lib/cifra/*, lib/uecc.c)
- OpenSSL backend implements key exchange, hashes, ciphers, AEADs, signature selection/signing, certificate verification, tickets, and HPKE suites (`lib/openssl.c:1809`, `lib/openssl.c:2003`, `lib/openssl.c:2094`, `lib/openssl.c:2375`).
- mbedTLS backend wraps PSA Crypto for hashes, ciphers, AEADs, and key exchange (`lib/mbedtls.c:48`, `lib/mbedtls.c:354`).
- mbedTLS signing helper parses PEM/DER and creates a signing callback backed by PSA keys (`lib/mbedtls_sign.c:75`, `lib/mbedtls_sign.c:601`).
- Fusion backend provides SIMD-accelerated AES-ECB and AES-GCM plus QUIC-LB cipher and CPU feature detection (`lib/fusion.c:401`, `lib/fusion.c:2239`).
- Windows BCrypt backend provides AES-ECB/CTR/GCM and hash algorithm bindings (`lib/ptlsbcrypt.c:787`).
- Minicrypto backend wires Cifra primitives and micro-ecc key exchange/signing into zpicotls algorithm objects (`lib/cifra.c:26`, `lib/cifra/aes128.c:50`, `lib/cifra/aes256.c:55`, `lib/cifra/chacha20.c:100`, `lib/cifra/random.c:112`, `lib/cifra/x25519.c:129`, `lib/uecc.c:180`).

### Tests and tools (t/*.c, t/*.h)
- Shared test vectors, ECH configs, and FFX variant helpers (`t/test.h:23`).
- Utility helpers for loading certs/keys, logging, and session tickets (`t/util.h:52`).
- Core protocol and crypto tests for buffers, handshake, cipher selection, and ECH (`t/picotls.c:48`).
- OpenSSL backend tests for cipher suites, signatures, HPKE, and ECH (`t/openssl.c:101`).
- Minicrypto backend tests and handshake scenarios (`t/minicrypto.c:33`).
- mbedTLS backend tests for PSA random, key exchanges, and key loading (`t/mbedtls.c:53`).
- Fusion backend tests for AES-GCM and non-temporal modes (`t/fusion.c:32`).
- QUIC-LB test vectors (`t/quiclb.c:25`).
- HPKE test vectors and setup (`t/hpke.c:35`).
- CLI harness for running zpicotls over TCP with options for certificates, ECH, PSK, and logging (`t/cli.c:60`).
- Benchmark harness for AEAD throughput (`t/ptlsbench.c:67`).

### Vendored libraries
#### Cifra (deps/cifra/...)
Cifra provides the underlying symmetric crypto, hashes, DRBG, and tests used by the minicrypto backend and standalone tests.

#### micro-ecc (deps/micro-ecc/...)
micro-ecc provides secp256r1 key generation and ECDSA used by the minicrypto backend and comes with its own test programs.

## Code References
- **Key entrypoints**
- `lib/picotls.c:6033` - `ptls_handshake` drives the TLS handshake state machine.
- `lib/picotls.c:6096` - `ptls_receive` decrypts records into plaintext buffers.
- `lib/picotls.c:6156` - `ptls_send` encrypts application data into records.
- `lib/picotls.c:6179` - `ptls_update_key` triggers key update flows.
- `lib/picotls.c:6337` - `ptls_hkdf_extract` is the core HKDF extract used by key schedule and HPKE.
- `lib/picotls.c:6487` - `ptls_aead_new` creates AEAD contexts from a cipher suite.
- `lib/openssl.c:1809` - `ptls_openssl_init_sign_certificate` wires an OpenSSL key into the signing callback.
- `lib/openssl.c:2003` - `ptls_openssl_init_verify_certificate` sets up certificate verification with X509_STORE.
- `lib/mbedtls_sign.c:601` - `ptls_mbedtls_load_private_key` loads and imports a private key into PSA.
- `lib/fusion.c:401` - `ptls_fusion_aesgcm_encrypt` is the accelerated AES-GCM encoder.
- `lib/hpke.c:224` - `ptls_hpke_setup_base_s` performs HPKE sender setup.
- `lib/certificate_compression.c:122` - `ptls_init_compressed_certificate` precompresses certificate chains.
- `t/cli.c:60` - `shift_buffer` is part of the CLI record buffering loop.
- `t/ptlsbench.c:67` - `bench_time` provides timing for AEAD throughput measurement.
- **File index (all source.yaml files)**

- `deps/cifra/extra_vecs/openssl-hash.c:8` - Representative symbol `printhex` in this file.
- `deps/cifra/shitlisp/sl-cifra.c:11` - Representative symbol `aes_block_fn` in this file.
- `deps/cifra/src/aes.c:54` - Representative symbol `word4` in this file.
- `deps/cifra/src/aes.h:28` - Representative symbol `AES_H` in this file.
- `deps/cifra/src/arm/boot.c:57` - Representative symbol `Reset_Handler` in this file.
- `deps/cifra/src/arm/ext/cutest.h:22` - Representative symbol `test_check__` in this file.
- `deps/cifra/src/arm/main.c:22` - Representative symbol `do_nothing` in this file.
- `deps/cifra/src/arm/semihost.c:16` - Representative symbol `quit_success` in this file.
- `deps/cifra/src/arm/semihost.h:2` - Representative symbol `SEMIHOST_H` in this file.
- `deps/cifra/src/arm/unacl/scalarmult.c:140` - Representative symbol `fe25519_cpy` in this file.
- `deps/cifra/src/bitops.h:29` - Representative symbol `rotr32` in this file.
- `deps/cifra/src/blockwise.c:22` - Representative symbol `cf_blockwise_accumulate` in this file.
- `deps/cifra/src/blockwise.h:16` - Representative symbol `BLOCKWISE_H` in this file.
- `deps/cifra/src/cbcmac.c:25` - Representative symbol `cf_cbcmac_stream_init` in this file.
- `deps/cifra/src/ccm.c:24` - Representative symbol `write_be` in this file.
- `deps/cifra/src/cf_config.h:16` - Representative symbol `CF_CONFIG_H` in this file.
- `deps/cifra/src/chacha20.c:23` - Representative symbol `cf_chacha20_core` in this file.
- `deps/cifra/src/chacha20poly1305.c:27` - Representative symbol `process` in this file.
- `deps/cifra/src/chacha20poly1305.h:16` - Representative symbol `CHACHA20POLY1305_H` in this file.
- `deps/cifra/src/chash.c:19` - Representative symbol `cf_hash` in this file.
- `deps/cifra/src/chash.h:16` - Representative symbol `CHASH_H` in this file.
- `deps/cifra/src/cmac.c:25` - Representative symbol `cf_cmac_init` in this file.
- `deps/cifra/src/curve25519.c:18` - Representative symbol `cf_curve25519_mul` in this file.
- `deps/cifra/src/curve25519.donna.c:70` - Representative symbol `fsum` in this file.
- `deps/cifra/src/curve25519.h:16` - Representative symbol `CURVE25519_H` in this file.
- `deps/cifra/src/curve25519.naclref.c:9` - Representative symbol `add` in this file.
- `deps/cifra/src/curve25519.tweetnacl.c:39` - Representative symbol `set25519` in this file.
- `deps/cifra/src/drbg.c:25` - Representative symbol `hash_df` in this file.
- `deps/cifra/src/drbg.h:16` - Representative symbol `DRBG_H` in this file.
- `deps/cifra/src/eax.c:22` - Representative symbol `cmac_compute_n` in this file.
- `deps/cifra/src/ext/cutest.h:142` - Representative symbol `test_print_in_color` in this file.
- `deps/cifra/src/ext/handy.h:41` - Representative symbol `mem_clean` in this file.
- `deps/cifra/src/gcm.c:29` - Representative symbol `ghash_init` in this file.
- `deps/cifra/src/gf128.c:21` - Representative symbol `cf_gf128_tobytes_be` in this file.
- `deps/cifra/src/gf128.h:16` - Representative symbol `GF128_H` in this file.
- `deps/cifra/src/hmac.c:23` - Representative symbol `cf_hmac_init` in this file.
- `deps/cifra/src/hmac.h:16` - Representative symbol `HMAC_H` in this file.
- `deps/cifra/src/modes.c:24` - Representative symbol `cf_cbc_init` in this file.
- `deps/cifra/src/modes.h:16` - Representative symbol `MODES_H` in this file.
- `deps/cifra/src/norx.c:43` - Representative symbol `permute` in this file.
- `deps/cifra/src/norx.h:16` - Representative symbol `NORX_H` in this file.
- `deps/cifra/src/ocb.c:52` - Representative symbol `ocb_init` in this file.
- `deps/cifra/src/pbkdf2.c:23` - Representative symbol `F` in this file.
- `deps/cifra/src/pbkdf2.h:16` - Representative symbol `PBKDF2_H` in this file.
- `deps/cifra/src/poly1305.c:23` - Representative symbol `cf_poly1305_init` in this file.
- `deps/cifra/src/poly1305.h:16` - Representative symbol `POLY1305_H` in this file.
- `deps/cifra/src/prp.h:16` - Representative symbol `PRP_H` in this file.
- `deps/cifra/src/salsa20.c:22` - Representative symbol `cf_salsa20_core` in this file.
- `deps/cifra/src/salsa20.h:16` - Representative symbol `SALSA20_H` in this file.
- `deps/cifra/src/sha1.c:23` - Representative symbol `cf_sha1_init` in this file.
- `deps/cifra/src/sha1.h:16` - Representative symbol `SHA1_H` in this file.
- `deps/cifra/src/sha2.h:16` - Representative symbol `SHA2_H` in this file.
- `deps/cifra/src/sha256.c:49` - Representative symbol `cf_sha256_init` in this file.
- `deps/cifra/src/sha3.c:60` - Representative symbol `shuffle_out` in this file.
- `deps/cifra/src/sha3.h:16` - Representative symbol `SHA3_H` in this file.
- `deps/cifra/src/sha512.c:73` - Representative symbol `cf_sha512_init` in this file.
- `deps/cifra/src/tassert.h:16` - Representative symbol `TASSERT_H` in this file.
- `deps/cifra/src/testaes.c:24` - Representative symbol `test_memclean` in this file.
- `deps/cifra/src/testchacha20poly1305.c:20` - Representative symbol `vector` in this file.
- `deps/cifra/src/testcurve25519.c:20` - Representative symbol `test_base_mul` in this file.
- `deps/cifra/src/testdrbg.c:23` - Representative symbol `test_hashdrbg_sha256_vector` in this file.
- `deps/cifra/src/testmodes.c:31` - Representative symbol `test_cbc` in this file.
- `deps/cifra/src/testnorx.c:20` - Representative symbol `test_vector` in this file.
- `deps/cifra/src/testpoly1305.c:22` - Representative symbol `check` in this file.
- `deps/cifra/src/testsalsa20.c:21` - Representative symbol `test_salsa20_core` in this file.
- `deps/cifra/src/testsha.h:23` - Representative symbol `vector` in this file.
- `deps/cifra/src/testsha1.c:23` - Representative symbol `test_sha1` in this file.
- `deps/cifra/src/testsha2.c:26` - Representative symbol `test_sha224` in this file.
- `deps/cifra/src/testsha3.c:21` - Representative symbol `test_sha3_224` in this file.
- `deps/cifra/src/testutil.h:22` - Representative symbol `unhex_chr` in this file.
- `deps/micro-ecc/test/ecdsa_test_vectors.c:37` - Representative symbol `vli_print` in this file.
- `deps/micro-ecc/test/public_key_test_vectors.c:259` - Representative symbol `vli_print` in this file.
- `deps/micro-ecc/test/test_compress.c:12` - Representative symbol `vli_print` in this file.
- `deps/micro-ecc/test/test_compute.c:8` - Representative symbol `vli_print` in this file.
- `deps/micro-ecc/test/test_ecdh.c:8` - Representative symbol `vli_print` in this file.
- `deps/micro-ecc/test/test_ecdsa.c:8` - Representative symbol `main` in this file.
- `deps/micro-ecc/types.h:4` - Representative symbol `_UECC_TYPES_H_` in this file.
- `deps/micro-ecc/uECC.c:166` - Representative symbol `bcopy` in this file.
- `deps/micro-ecc/uECC.h:4` - Representative symbol `_UECC_H_` in this file.
- `deps/micro-ecc/uECC_vli.h:4` - Representative symbol `_UECC_VLI_H_` in this file.
- `deps/picotest/picotest.c:31` - Representative symbol `indent` in this file.
- `deps/picotest/picotest.h:23` - Representative symbol `picotest_h` in this file.
- `include/zpicotls.h:1987` - Representative symbol `ptls_log_point_maybe_active` in this file.
- `include/zpicotls/asn1.h:18` - Representative symbol `PTLS_ASN1_H` in this file.
- `include/zpicotls/certificate_compression.h:23` - Representative symbol `picotls_certificate_compression_h` in this file.
- `include/zpicotls/ffx.h:18` - Representative symbol `PTLS_FFX_H` in this file.
- `include/zpicotls/fusion.h:23` - Representative symbol `picotls_fusion_h` in this file.
- `include/zpicotls/mbedtls.h:23` - Representative symbol `picotls_mbedtls_h` in this file.
- `include/zpicotls/minicrypto.h:23` - Representative symbol `picotls_minicrypto_h` in this file.
- `include/zpicotls/openssl.h:23` - Representative symbol `picotls_openssl_h` in this file.
- `include/zpicotls/pembase64.h:18` - Representative symbol `PTLS_PEMBASE64_H` in this file.
- `include/zpicotls/ptlsbcrypt.h:23` - Representative symbol `picotls_bcrypt_h` in this file.
- `lib/asn1.c:46` - Representative symbol `ptls_asn1_print_indent` in this file.
- `lib/certificate_compression.c:28` - Representative symbol `decompress_certificate` in this file.
- `lib/chacha20poly1305.h:39` - Representative symbol `chacha20poly1305_write_u64` in this file.
- `lib/cifra.c:26` - Representative symbol `ptls_minicrypto_cipher_suites` in this file.
- `lib/cifra/aes-common.h:35` - Representative symbol `aesecb_dispose` in this file.
- `lib/cifra/aes128.c:24` - Representative symbol `aes128ecb_setup_crypto` in this file.
- `lib/cifra/aes256.c:24` - Representative symbol `aes256ecb_setup_crypto` in this file.
- `lib/cifra/chacha20.c:38` - Representative symbol `chacha20_dispose` in this file.
- `lib/cifra/libaegis.c:26` - Representative symbol `ptls_minicrypto_aegis128l` in this file.
- `lib/cifra/random.c:44` - Representative symbol `read_entropy` in this file.
- `lib/cifra/x25519.c:35` - Representative symbol `x25519_create_keypair` in this file.
- `lib/ffx.c:32` - Representative symbol `ptls_ffx_setup_crypto` in this file.
- `lib/fusion.c:127` - Representative symbol `transformH` in this file.
- `lib/hpke.c:27` - Representative symbol `build_suite_id` in this file.
- `lib/libaegis.h:35` - Representative symbol `aegis128l_get_iv` in this file.
- `lib/mbedtls.c:48` - Representative symbol `ptls_mbedtls_random_bytes` in this file.
- `lib/mbedtls_sign.c:75` - Representative symbol `ptls_mbedtls_parse_der_length` in this file.
- `lib/minicrypto-pem.c:40` - Representative symbol `ptls_minicrypto_asn1_decode_private_key` in this file.
- `lib/openssl.c:84` - Representative symbol `HMAC_CTX_new` in this file.
- `lib/pembase64.c:55` - Representative symbol `ptls_base64_cell` in this file.
- `lib/picotls.c:447` - Representative symbol `is_supported_version` in this file.
- `lib/ptlsbcrypt.c:28` - Representative symbol `ptls_bcrypt_init` in this file.
- `lib/quiclb-impl.h:41` - Representative symbol `picotls_quiclb_cipher_aes` in this file.
- `lib/uecc.c:45` - Representative symbol `secp256r1_on_exchange` in this file.
- `t/cli.c:60` - Representative symbol `shift_buffer` in this file.
- `t/fusion.c:32` - Representative symbol `tostr` in this file.
- `t/hpke.c:35` - Representative symbol `test_one_hpke` in this file.
- `t/mbedtls.c:53` - Representative symbol `random_trial` in this file.
- `t/minicrypto.c:33` - Representative symbol `test_secp256r1_key_exchange` in this file.
- `t/openssl.c:101` - Representative symbol `test_bf` in this file.
- `t/picotls.c:48` - Representative symbol `reset_buffer_alloc_tracking` in this file.
- `t/ptlsbench.c:67` - Representative symbol `bench_time` in this file.
- `t/quiclb.c:25` - Representative symbol `test_quiclb` in this file.
- `t/test.h:23` - Representative symbol `test_h` in this file.
- `t/util.h:52` - Representative symbol `load_certificate_chain` in this file.

## Architecture Documentation
The architecture centers on `ptls_context_t` (configuration and callbacks) and `ptls_t` (per-connection state) defined in `include/zpicotls.h`. The core protocol engine in `lib/picotls.c` consumes the context’s key exchange list and cipher suite list to negotiate algorithms and drive the TLS 1.3/1.2 handshake, emit messages, and manage record protection. Cryptographic operations are abstracted through `ptls_cipher_algorithm_t`, `ptls_aead_algorithm_t`, `ptls_hash_algorithm_t`, and `ptls_key_exchange_algorithm_t`, with concrete implementations supplied by backends in `lib/openssl.c`, `lib/mbedtls.c`, `lib/fusion.c`, `lib/ptlsbcrypt.c`, and the in-tree minicrypto components (`lib/cifra/*`, `lib/uecc.c`).

Feature modules plug into the core via callback interfaces: certificate compression exposes `ptls_emit_certificate_t` and `ptls_decompress_certificate_t`, HPKE helpers build on `ptls_hkdf_extract`/`ptls_hkdf_expand` and AEAD creation, and QUIC-LB helpers provide a cipher transform callable from multiple backends. PEM and ASN.1 utilities support key and certificate loading for both tests and runtime tools. Logging is implemented in `lib/picotls.c` and surfaced via log callbacks and helper APIs in `include/zpicotls.h`, while the CLI (`t/cli.c`) and tests (`t/*.c`) demonstrate composition of contexts, credentials, and handshake properties across backends.

## Open Questions
- Behavior of external libraries (OpenSSL, mbedTLS/PSA, brotli, Cifra, micro-ecc) depends on their versions and configuration; this report only reflects their integration points as seen in this code.
- Some tests reference assets under `t/assets/` and other non-`*.c`/`*.h` files that are outside the source.yaml scope, so their contents are not described here.
- Feature coverage depends on compile-time flags (e.g., `PTLS_HAVE_AEGIS`, `PTLS_HAVE_FUSION`, `PICOTLS_USE_BROTLI`, `PTLS_OPENSSL_HAVE_*`).
