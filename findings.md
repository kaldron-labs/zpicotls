# Review of uncommitted work

The findings below describe the pre-repair snapshot. See the resolution section for the implemented repairs.

Scope: all ten tracked modified files and `review.md`, against the local HEAD. This is a review only; implementation files were not changed. Upstream consistency observations use the existing picotls architecture and pre-change code, rather than a claim of comparison with a freshly fetched upstream revision.

## Findings

### 1. [P1] Outbound sink failures leave a usable object with unpublished sequence/key changes

Locations: `lib/picotls.c:939`, `lib/picotls.c:977`, `lib/picotls.c:6923`–`6940`; public contract at `include/zpicotls.h:355` and `include/zpicotls.h:1829`.

`record_emitv` advances the encryption sequence before the sink finishes. `ptls_tx_send_chunks` can additionally install a new traffic key and clear the pending-update flags before `finish`. If a later chunk, commit, or finish fails, discard removes the output but neither restores protocol state nor prevents another send. For example, a finish failure after encrypting the first application record discards sequence 0; the next call succeeds using sequence 1 while the peer still expects sequence 0. Losing a KeyUpdate transaction also leaves the peer on the old key. The header does not say that these errors make the Tx object terminal. Existing fault tests free the object immediately, so do not check this behavior.

Distinguish reservation failure (safe to retry) from failures after encryption begins. Mark the latter terminal and reject subsequent sends, or implement genuinely transactional state and publication. Document the rule for every chunks entry point and test a second send after a failed finish, both with and without a pending KeyUpdate. Do not merely decrement the sequence after a provider failure: avoiding nonce reuse needs an explicit policy.

### 2. [P2] Contiguous sends bypass the established optimized AEAD path

Locations: `lib/picotls.c:900`–`950`, `lib/picotls.c:1046`, `lib/picotls.c:7028`; `lib/fusion.c:1287`–`1490`.

The one-shot/vector branch in `record_emitv` is selected only when serial callbacks are absent. Installing the new callbacks therefore redirects ordinary `ptls_send`, `ptls_tx_sendv`, and handshake encryption through serial begin/chunk/end, even when the destination is fully contiguous. Fusion's existing `aead_do_encrypt_v_s` / `fusion_aesgcm_encrypt_iter` implementation is bypassed. The added six-pipeline AES/GHASH kernel duplicates substantial existing crypto machinery, and non-temporal mode now fences at each chunk (including the separate TLS 1.3 content-type chunk). Byte-equality tests cannot establish preservation of throughput.

Use the existing vector AEAD operation for admitted contiguous destinations and reserve serial operations for destinations that require them. Share low-level Fusion kernels where possible rather than maintaining independent AES/GHASH implementations. Benchmark full records, short records, and fragmented input before accepting a replacement of the existing fast path. This would also reduce divergence in the common upstream record-encryption flow.

### 3. [P2] Plaintext handshake commit rebuilds and copies an already complete record onto itself

Locations: `lib/picotls.c:1140`–`1152`, `lib/picotls.c:838`.

For a normal contiguous handshake buffer, the record header and body already exist. The new code fills the length, rewinds `off`, builds the same header again, and passes the existing body through `record_write`. Its `memcpy(dst, src, count)` receives identical source and destination pointers for the nonempty handshake body. This is redundant work and violates memcpy's non-overlap requirement; switching to memmove would address overlap but retain unnecessary traversal.

Keep the existing successful return for the contiguous plaintext case. Only emit into a separate sink when `record_sink` is set. This removes repeated formatting and copying and restores the pre-change behavior for canonical plaintext handshake emission.

### 4. [P2] Capability discovery constructs and destroys keyed AEADs for every connection

Locations: `lib/picotls.c:6603`–`6619`, `lib/picotls.c:6638`–`6654`.

Before accepting traffic, the streaming path walks both configured suite lists twice, constructing an encryption context and a decryption context for each suite using dummy keys. Those objects can allocate backend contexts, expand keys, and build Fusion GHASH tables solely to inspect callback pointers. The two cached flags are per connection, so they do not amortize this cost across connections; suites sharing an AEAD can repeat it even within one connection. None of these contexts participates in record protection.

Represent serial capabilities on the algorithm descriptor, or validate a fixed provider configuration once at context initialization with an explicit invalidation rule. Consolidate send/receive capability validation and check the actual selected context when installed. Do not blindly cache by pointer if callers can mutate provider configuration. This avoids the new temporary heap allocations and duplicated setup without introducing another per-record container.

## Other observations

- The receive carry arrays are bounded and serve distinct header, explicit-IV, and tag lifetimes. The copied sink descriptor is needed across calls. No new dynamically growing production container was introduced; replacing these arrays with heap containers would be counterproductive.
- Retaining provisional plaintext until authentication is necessary. The stream path correctly avoids ciphertext gathering and only dispatches authenticated encrypted records. Handshake-message gathering remains a separate protocol requirement; removing it would require changing the handshake parser's lifetime contract.
- The receive state is embedded in every connection, and seven new callbacks expand every AEAD context, including unsupported backends. This is a real footprint/API divergence, but a separate allocation is not automatically better. Measure the footprint before introducing an optional extension object.
- New crypto tests cover many chunk splits, AAD lengths, provider variants, bounds, and authentication failures. They do not establish performance or safe retry semantics after outbound publication failure.
- `PTLS_TEST_RECORD_CHUNKS` is defined in CMake but has no consumer. Remove it unless it is intended to control an actual test branch.

## Validation

- `cmake --build obj-x86_64-linux-gnu --target check -j4`: all targets built; exact-rx passed. The long randomized Fusion run was interrupted before suite completion; this is **not** a passing full-suite result. Log: `/tmp/zpicotls-review-check.log`.
- `obj-x86_64-linux-gnu/test-vector-tx.t`: passed, exit 0, all 18 top-level subtests. Log: `/tmp/zpicotls-review-vector.log`.
- `obj-x86_64-linux-gnu/test-openssl.t`: passed, exit 0. Log: `/tmp/zpicotls-review-openssl.log`.
- Findings 1–4 follow from inspected control flow; no timing regression magnitude or dynamic reproduction of the failed-send retry is claimed.

## Resolution

All four findings are repaired for release 2.0:

1. Successful sink admission followed by an output failure poisons outbound protection state. Both chunks and contiguous sends reject that state. Admission failure remains retryable. Tests exercise next/commit/finish failures with and without pending KeyUpdate, and reject follow-up publication. The public contract defines private commit, final publication, and teardown rules.
2. Contiguous destinations use the existing optimized vector operation. In-place handshake encryption uses the existing alias-safe vector API rather than the immutable-input API. A regression test keeps every serial callback installed and verifies that contiguous vector output never calls serial end. The bounded serial implementation remains for fragmented destinations and shares the existing Fusion keys and GHASH primitives; contiguous encryption no longer uses its alternate batching loop.
3. Already-formatted contiguous plaintext handshake records return directly after setting their length. They are neither reconstructed nor copied onto themselves.
4. Algorithm descriptors advertise serial capabilities. A shared validation routine inspects these without allocating or expanding dummy keys. Validation is uncached, so replacing suite lists does not leave stale capability decisions. Selected contexts are still checked for complete callbacks. Wrapper providers must clear capabilities they remove; tests verify zero setup calls during unsupported-provider admission.

The unused CMake test definition was removed. On x86-64, debug type inspection reports 48 bytes for `ptls_buffer_t`, 144 for `ptls_aead_context_t`, 112 for `ptls_aead_algorithm_t`, and 984 for the connection. The bounded receive state remains embedded; no extra allocation or container was introduced. Public layout changes are reflected in the 2.0 version and SONAME 2, with Debian and Arch package versions aligned.

Post-repair vector tests (18 top-level subtests) and OpenSSL tests (18) pass. A local TLS 1.2 AES-128-GCM benchmark exercised 64-, 1460-, and 16384-byte records with one and 64 source spans through OpenSSL and non-temporal Fusion. Results are workload observations, not a controlled before/after claim: full-record single-span throughput was approximately 11.5 GiB/s for OpenSSL and 0.82 GiB/s for non-temporal Fusion while the full test suite was running. Benchmark log: `/tmp/repair-benchmark.log`.

The full post-repair check is tracked separately in `/tmp/repair-check.log`; its final result will be recorded before merging.
