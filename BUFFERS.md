# `ptls_buffer_alloc` Use-Cases Grouped By Traffic Category

## Common allocation mechanics (applies to every category)
- `ptls_buffer_alloc` is called at one choke point: `lib/picotls.c:648` from `ptls_buffer_reserve_aligned` (`lib/picotls.c:620`).
- Reserve triggers callback when any condition at `lib/picotls.c:625`-`lib/picotls.c:626` is true:
1. `PTLS_MEMORY_DEBUG` is on (`lib/picotls.c:112`-`lib/picotls.c:113`).
2. `buf->capacity < buf->off + delta`.
3. Current pointer does not satisfy requested stronger alignment.
- Wrapper stack:
1. `ptls_buffer_reserve` -> `ptls_buffer_reserve_aligned` (`lib/picotls.c:615`, `lib/picotls.c:617`).
2. `ptls_buffer__do_pushv` -> `ptls_buffer_reserve` (`lib/picotls.c:655`, `lib/picotls.c:661`).
3. `ptls_buffer_push*` macros -> `ptls_buffer__do_pushv` (`include/picotls.h:1234`, `include/picotls.h:1240`, `include/picotls.h:1236`, `include/picotls.h:1242`).

## Shared receive-side allocation paths (used by multiple RX categories)
- Incremental record reassembly (slow path): `lib/picotls.c:5096`, `lib/picotls.c:5112`.
- TLS 1.3 decrypted-record staging buffer: `lib/picotls.c:5898`.
- TLS 1.2 decrypted-record staging buffer: `lib/picotls.c:5994`.
- Handshake-message coalescing buffer (when handshake messages span records): `lib/picotls.c:5823`, `lib/picotls.c:5857`.

## Shared transmit-side allocation paths (used by multiple TX categories)
- Encrypted record emission (chunked path): `lib/picotls.c:786`, `lib/picotls.c:809`.
- In-place record encryption overhead growth: `lib/picotls.c:833`.

## Handshake RX
Direct reserve sites:
- Shared RX paths listed above: `lib/picotls.c:5096`, `lib/picotls.c:5112`, `lib/picotls.c:5898`, `lib/picotls.c:5823`, `lib/picotls.c:5857`.
- NewSessionTicket receive/save path reserve: `lib/picotls.c:3548`.
- PSK ticket decrypt callback output reserve (OpenSSL helper implementations): `lib/openssl.c:2201`, `lib/openssl.c:2349`.
  - These are reached from handshake receive flow via ticket decryption callback usage in `lib/picotls.c:4157`.
- HPKE receiver key schedule reserve (SetupBaseR path): `lib/hpke.c:190`, `lib/hpke.c:195`.

Indirect push-based allocation sites in handshake RX logic:
- ECH CH reconstruction on receive:
  - `lib/picotls.c:3926`, `lib/picotls.c:3957`, `lib/picotls.c:3964`, `lib/picotls.c:3990`, `lib/picotls.c:3995`, `lib/picotls.c:4003`, `lib/picotls.c:4012`, `lib/picotls.c:4013`.
- Ticket persistence buffer construction in `client_handle_new_session_ticket`:
  - `lib/picotls.c:3543`, `lib/picotls.c:3544`, `lib/picotls.c:3545`, `lib/picotls.c:3546`, `lib/picotls.c:3547`.

## Handshake TX
Direct reserve sites:
- ClientHello construction placeholders and padding:
  - `lib/picotls.c:2207`, `lib/picotls.c:2319`, `lib/picotls.c:2339`, `lib/picotls.c:2523`.
- Finished / ticket material generation:
  - `lib/picotls.c:1735`, `lib/picotls.c:1871`, `lib/picotls.c:1904`.
- ServerHello / HRR placeholder regions:
  - `lib/picotls.c:4318`, `lib/picotls.c:4594`, `lib/picotls.c:4610`, `lib/picotls.c:4623`.
- Shared TX paths listed above (handshake records are encrypted through them):
  - `lib/picotls.c:786`, `lib/picotls.c:809`, `lib/picotls.c:833`.
- Signature callback output reserves:
  - OpenSSL: `lib/openssl.c:1185`, `lib/openssl.c:1228`.
  - mbedTLS signer: `lib/mbedtls_sign.c:481`.
- Ticket encryption callback output reserve:
  - OpenSSL helpers: `lib/openssl.c:2111`, `lib/openssl.c:2249`.
- HPKE sender key schedule reserve (SetupBaseS path): `lib/hpke.c:190`, `lib/hpke.c:195`.
  - Core handshake TX use-site is ECH setup at `lib/picotls.c:1166`.

Indirect push-based allocation sites in handshake TX logic:
- ECH info construction: `lib/picotls.c:1164`, `lib/picotls.c:1165`.
- Session identifier encoding: `lib/picotls.c:1728`, `lib/picotls.c:1730`, `lib/picotls.c:1732`, `lib/picotls.c:1734`, `lib/picotls.c:1742`, `lib/picotls.c:1744`, `lib/picotls.c:1746`, `lib/picotls.c:1748`, `lib/picotls.c:1750`, `lib/picotls.c:1752`, `lib/picotls.c:1756`, `lib/picotls.c:1758`.
- Finished and NST message construction:
  - `lib/picotls.c:1870`, `lib/picotls.c:1900`, `lib/picotls.c:1903`, `lib/picotls.c:1924`, `lib/picotls.c:1925`, `lib/picotls.c:1926`, `lib/picotls.c:1927`, `lib/picotls.c:1928`, `lib/picotls.c:1933`, `lib/picotls.c:1936`.
- Additional handshake-message helper emitters:
  - `lib/picotls.c:1967`, `lib/picotls.c:1982`, `lib/picotls.c:1997`, `lib/picotls.c:1999`, `lib/picotls.c:2075`, `lib/picotls.c:2076`, `lib/picotls.c:2138`, `lib/picotls.c:2139`, `lib/picotls.c:2140`, `lib/picotls.c:3485`.
- ClientHello emit path: `lib/picotls.c:2173` through `lib/picotls.c:2347` (notable push call lines include `lib/picotls.c:2175`, `lib/picotls.c:2177`, `lib/picotls.c:2192`, `lib/picotls.c:2200`, `lib/picotls.c:2227`, `lib/picotls.c:2316`, `lib/picotls.c:2337`).
- Certificate / CertificateVerify emit path:
  - `lib/picotls.c:3131`, `lib/picotls.c:3132`, `lib/picotls.c:3135`, `lib/picotls.c:3136`, `lib/picotls.c:3139`, `lib/picotls.c:3140`, `lib/picotls.c:3158`, `lib/picotls.c:3209`, `lib/picotls.c:3212`, `lib/picotls.c:3213`.
- ServerHello / EncryptedExtensions / CertificateRequest emit path:
  - `lib/picotls.c:4315`, `lib/picotls.c:4317`, `lib/picotls.c:4324`, `lib/picotls.c:4325`, `lib/picotls.c:4326`, `lib/picotls.c:4327`, `lib/picotls.c:4328`, `lib/picotls.c:4330`, `lib/picotls.c:4348`, `lib/picotls.c:4558`, `lib/picotls.c:4603`, `lib/picotls.c:4606`, `lib/picotls.c:4608`, `lib/picotls.c:4616`, `lib/picotls.c:4621`, `lib/picotls.c:4767`, `lib/picotls.c:4768`, `lib/picotls.c:4773`, `lib/picotls.c:4811`, `lib/picotls.c:4813`, `lib/picotls.c:4821`, `lib/picotls.c:4825`, `lib/picotls.c:4826`, `lib/picotls.c:4827`, `lib/picotls.c:4838`, `lib/picotls.c:4842`, `lib/picotls.c:4851`, `lib/picotls.c:4855`, `lib/picotls.c:4857`, `lib/picotls.c:4865`, `lib/picotls.c:4867`, `lib/picotls.c:4869`.
- Async OpenSSL signature completion push (still handshake TX output path): `lib/openssl.c:1143`.
- HPKE buffer-build pushes used during ECH/HPKE handshake setup:
  - `lib/hpke.c:32`, `lib/hpke.c:33`, `lib/hpke.c:35`, `lib/hpke.c:36`, `lib/hpke.c:37`, `lib/hpke.c:38`, `lib/hpke.c:56`, `lib/hpke.c:59`, `lib/hpke.c:60`, `lib/hpke.c:81`, `lib/hpke.c:82`, `lib/hpke.c:85`, `lib/hpke.c:86`, `lib/hpke.c:105`, `lib/hpke.c:106`, `lib/hpke.c:189`.
- Signature/certificate helper pushes used by handshake TX callbacks:
  - `lib/uecc.c:164`, `lib/uecc.c:165`, `lib/uecc.c:167`.
  - `lib/certificate_compression.c:73`, `lib/certificate_compression.c:74`, `lib/certificate_compression.c:75`, `lib/certificate_compression.c:76`.
  - PEM/base64 decode push path used by cert/key loading: `lib/pembase64.c:186`.

## Key Update RX
Direct reserve sites:
- Shared RX record/decrypt paths: `lib/picotls.c:5096`, `lib/picotls.c:5112`, `lib/picotls.c:5898`.
- If KeyUpdate handshake message is split/coalesced, handshake-message buffer reserves also apply: `lib/picotls.c:5823`, `lib/picotls.c:5857`.

Key-update-specific handler notes:
- `handle_key_update` itself does not call reserve directly: `lib/picotls.c:5023`.

Indirect push-based allocation sites:
- None specific to KeyUpdate RX (uses shared receive machinery above).

## Key Update TX
Direct reserve sites:
- Message emit uses shared TX encryption path (in-place overhead reserve): `lib/picotls.c:833`.
  - (KeyUpdate records are tiny; the chunking reserves `lib/picotls.c:786`, `lib/picotls.c:809` are not the normal path here.)

Indirect push-based allocation sites:
- KeyUpdate handshake message construction:
  - `lib/picotls.c:6141`, `lib/picotls.c:6142`.

## Application Data RX
Direct reserve sites:
- Shared RX record reassembly: `lib/picotls.c:5096`, `lib/picotls.c:5112`.
- TLS 1.3 app-data decrypt staging: `lib/picotls.c:5898`.
- TLS 1.2 app-data decrypt staging: `lib/picotls.c:5994`.

Indirect push-based allocation sites:
- None in the app-data RX path (decrypted bytes are written directly into caller-supplied `decryptbuf`).

## Application Data TX
Direct reserve sites:
- `ptls_send` app-data encryption path uses chunk reserves:
  - TLS 1.2 style record reserve: `lib/picotls.c:786`.
  - TLS 1.3 style record reserve: `lib/picotls.c:809`.
  - Entrypoint: `lib/picotls.c:6153`, `lib/picotls.c:6173`.

Indirect push-based allocation sites:
- None in normal app-data TX (ciphertext written directly into reserved space).

## Cross-cutting path that can occur in any of the six categories
- Thread-local JSON log buffer growth: `lib/picotls.c:6972`.
  - This allocation is tied to logging emission, not to one single protocol direction/message type.
- Alert record construction uses push-based reserve and can be triggered from handshake, key-update, or application contexts:
  - `lib/picotls.c:6200`.
- Key-schedule label scratch buffer uses pushes and can be reached by handshake and key-update secret derivation paths:
  - `lib/picotls.c:6389`, `lib/picotls.c:6390`, `lib/picotls.c:6393`, `lib/picotls.c:6394`, `lib/picotls.c:6396`.
- Export / serialization utility APIs (not tied to a single wire-direction) also use push/reserve:
  - `lib/picotls.c:5209`, `lib/picotls.c:5210`, `lib/picotls.c:5211`, `lib/picotls.c:5212`, `lib/picotls.c:5213`, `lib/picotls.c:5214`, `lib/picotls.c:5215`, `lib/picotls.c:5217`, `lib/picotls.c:5219`, `lib/picotls.c:5220`, `lib/picotls.c:5221`, `lib/picotls.c:5222`, `lib/picotls.c:5235`, `lib/picotls.c:5236`, `lib/picotls.c:5237`, `lib/picotls.c:5239`, `lib/picotls.c:5240`, `lib/picotls.c:5241`, `lib/picotls.c:5242`, `lib/picotls.c:5304`, `lib/picotls.c:5305`, `lib/picotls.c:5306`, `lib/picotls.c:5307`, `lib/picotls.c:6710`, `lib/picotls.c:6711`, `lib/picotls.c:6712`, `lib/picotls.c:6713`, `lib/picotls.c:6714`, `lib/picotls.c:6715`, `lib/picotls.c:6717`, `lib/picotls.c:6718`, `lib/picotls.c:6721`, `lib/picotls.c:6722`, `lib/picotls.c:6723`.

## Header/API references relevant to all categories
- Reserve API declarations: `include/picotls.h:1208`, `include/picotls.h:1212`.
- Generic push/reserve macro definitions:
  - `include/picotls.h:1234`, `include/picotls.h:1240`, `include/picotls.h:1271`, `include/picotls.h:1273`, `include/picotls.h:1279`, `include/picotls.h:1318`, `include/picotls.h:1329`.
- No direct `ptls_buffer_reserve*` call-sites exist under `src/`.
