# Fork Reconciliation Review

Date: 2026-05-18

## Scope

Reviewed local `master` at `600d5ce9c8d4a9f8fbeef7cb892887c4776ced6b`, including the current unstaged diffs in:

- `include/picotls.h`
- `include/picotls/openssl.h`
- `lib/fusion.c`
- `t/fusion.c`

Fetched canonical upstream into local ref `upstream/master`:

- upstream head: `7c32032f91449d695b24b82955f20d04d47e6cff` (`Merge pull request #598 from dip-proto/rsa-pkcs8-import-slices-wrong-der-object`, 2026-05-08)
- merge base with fork: `34d4d6496cec80bc3b56dbdab45f21bd9fbc17aa`
- divergence from merge base: 44 fork-only commits, 53 upstream-only commits

## Recommendation

Merge upstream `upstream/master` into this fork rather than cherry-picking individual fixes. The upstream side is compact, touches only 15 files from the merge base, and includes several security, correctness, and toolchain compatibility fixes that should not be left behind.

The merge should preserve fork-only additions such as packaging/install metadata, MinGW work, buffer allocator hooks, buffer direction tagging, and local documentation. The simulated merge, including the current unstaged working tree, reports one real content conflict in `lib/picotls.c`; other overlapping files auto-merge.

## Upstream Changes To Bring In

High priority upstream changes:

- Security and parser hardening:
  - `b94f08f` fixes an ASN.1 type-and-length out-of-bounds read.
  - `2146bd9` adds RSA key-bit parser bounds checks.
  - `0e54cc0` rejects undersized bcrypt AEAD ciphertext before tag subtraction.
  - `be4ac87` fixes TLS 1.2 receive-path error propagation.
- TLS/ECH correctness:
  - `b1d103e` and `47c9ba3` fix CCS and certificate-alert behavior.
  - `71fb2fc` plus the surrounding ECH refactor/test commits fix grease ECH 0-RTT resumption.
  - `61fd8f1` rejects the HRR-accepted/ServerHello-rejected ECH path with `illegal_parameter`.
  - `a83ce98` makes `{NULL, 0}` ECH configs mean "do not send ECH", even when ECH ciphers exist.
- Interop and backend fixes:
  - `8f00e1c` raises the signature algorithm list limit to 64 for large modern client lists.
  - `22e1673`, `22b7b01`, and `f985d95` fix mbedTLS key/signature and AES-CTR issues.
  - `b1a50a1` updates libaegis 0.9 call sites.
  - `314a139` / `31d156a` fix OpenSSL 3.5 builds without ENGINE APIs.
  - `3960696` fixes malformed Brotli link-directory handling.
- Fusion backend:
  - `e8ea612`, `2d5934d`, `371ca8c`, `817131c` add allocation-failure checks/assertions around AES-GCM capacity growth and setup.
  - `78448b4` adds public comments for fusion algorithms.

## Merge Mechanics

`git merge-tree --write-tree <working-tree-snapshot> upstream/master` reports one conflict:

- `lib/picotls.c`, inside ClientHello PSK identity emission.

The required resolution is mechanical: combine the fork's new buffer-direction argument with upstream's ECH grease condition. The resolved code should keep both behaviors:

```c
if (mode == ENCODE_CH_MODE_OUTER && ech->state != PTLS_ECH_STATE_GREASE) {
    if ((ret = ptls_buffer_reserve(sendbuf, psk_identity.len, 1)) != 0)
        goto Exit;
    ctx->random_bytes(sendbuf->base + sendbuf->off, psk_identity.len);
    sendbuf->off += psk_identity.len;
} else {
    ptls_buffer_pushv(sendbuf, psk_identity.base, psk_identity.len);
}
```

The nearby `obfuscated_ticket_age` branch should also retain upstream's `ech->state != PTLS_ECH_STATE_GREASE` condition.

After resolving, search the merged tree for old two-argument `ptls_buffer_reserve(...)` calls. The simulated merge showed only the conflict marker carrying the old call signature, but this is worth rechecking after manual resolution.

## Local Change Review

### Buffer API and allocator hooks

The direction split and allocator hooks are architecturally coherent for the stated goal: callers can distinguish receive-side and transmit-side growth, and custom allocators can observe `origin`, alignment, capacity, and direction. The tests in `t/picotls.c` cover basic allocation, alignment, failure preservation, and RX/TX paths.

There are important issues to fix before treating this API as stable:

- `include/picotls.h:351-359`, `include/picotls.h:1198-1222`: changing `ptls_buffer_t.capacity`, `ptls_buffer_t.off`, `ptls_buffer_reserve`, and `ptls_buffer_init` from `size_t`/three-argument APIs to `uint32_t`/direction-aware APIs is a source and ABI break. It also constrains a public utility buffer to 4 GiB. If this fork intends to remain upstream-compatible, prefer keeping `size_t` fields and adding direction metadata without narrowing existing fields.
  - RESOLUTION: keep `size_t` fields, add direction metadata
- `lib/picotls.c:635`: `buf->off + delta` is now 32-bit arithmetic. If the addition wraps, reserve can skip growth and later writes can overflow the allocation. Add an explicit overflow check, or keep `size_t` and validate any allocator-specific maximum separately.
  - RESOLUTION: keep `size_t` and validate any allocator-specific maximum separately
- `include/picotls.h:1289-1304`: `ptls_buffer_push_block(buf, -1, ...)` support was removed. That was the QUIC-varint length path. External callers using the existing public macro with `-1` now hit a huge `size_t` capacity and undefined behavior. Either restore the `capacity == (size_t)-1` branch and `ptls_buffer__adjust_quic_blocksize`, or add a new explicit QUIC block API and keep the old macro safe.
  - RESOLUTION: restore the `capacity == (size_t)-1` branch and `ptls_buffer__adjust_quic_blocksize`
- `picotlsvs/picotlsvs/picotlsvs.c:146` and `picotlsvs/picotlsvs/picotlsvs.c:158` still call the old `ptls_buffer_init(sendbuf, "", 0)` signature. The Visual Studio sample/project path will not compile against the new public header until these become `ptls_buffer_init_tx(...)` or equivalent.
  - RESOLUTION: convert these calls
- `include/picotls.h:1945-1958`: the `ptls_buffer_free` comment says "returns NULL on failure", but the hook returns `void`. Fix the documentation.
  - RESOLUTION: fix the documentation

### Build, install, and packaging

The install and pkg-config work is useful, especially for downstream packaging. It should be kept, but cleaned up as part of reconciliation:

- `CMakeLists.txt:292-405`: use `GNUInstallDirs` rather than open-coded defaults for `CMAKE_INSTALL_INCLUDEDIR` and `CMAKE_INSTALL_LIBDIR`; this aligns with CMake packaging conventions and distro expectations.
- `CMakeLists.txt:247-253`: the Windows library additions refer to `test-fusion.t` unconditionally. If `WITH_FUSION` is off or unavailable on Windows, this can fail at configure time. Guard with `if (TARGET test-fusion.t)`.
- `CMakeLists.txt:230-232`: disabling `check` on Windows makes the new Windows CI build-only. That may be intentional for MinGW bring-up, but it should be called out as reduced coverage.
- `PKGBUILD:1-40` is explicitly local-development packaging. Keep it out of any upstream-facing PR unless it is converted into a normal Arch package recipe with source/check handling.

### Current unstaged fusion `do_encrypt_v` patch

The unstaged `lib/fusion.c:1146-1187` implementation makes fusion AES-GCM support vector input by coalescing input fragments, then calling the one-shot encryptor. The focused fusion tests now enable multivec for fusion and pass.

This is probably correct for the tested non-overlapping cases, but it needs a little hardening before merge:

- The new code should be merged with upstream's allocation-failure assertions in `aead_do_encrypt`, `aead_do_decrypt`, and setup paths. Current unstaged lines `lib/fusion.c:1141-1143` and `lib/fusion.c:1197-1200` still lack the upstream assertions after `ptls_fusion_aesgcm_set_capacity`.
  - RESOLUTION: add the upstream assertions
- Add tests for in-place vector encryption and partially overlapping input/output. The implementation has overlap handling, but `t/fusion.c:430-435` only exercises separate `text` and `encrypted` buffers.
  - RESOLUTION: add the suggested tests
- Consider whether per-record `malloc(inlen)` is acceptable on the hot path when overlap forces a temporary buffer. It is only used for multi-vector overlap, but it is still in an optimized backend.
  - RESOLUTION: per-record `malloc(inlen)` is NOT acceptable, suggest alternatives
- `abort()` on temporary allocation failure is consistent with upstream's "fusion assumes memory is available" direction, but use the same style as upstream after the merge to avoid two failure policies in one backend.
  - RESOLUTION: adopt same style as upstream

The unstaged `include/picotls/openssl.h` documentation update is correct: async users should call `ptls_get_async_job(...)->get_fd(...)`; there is no longer a `ptls_openssl_get_async_fd` API in this tree.

## Architectural Alignment

The fork is moving picotls in two directions: packaging/installability and memory-buffer ownership control. Both fit downstream integration needs, but the buffer work is invasive enough that it should be treated as an API fork unless compatibility is restored.

The most upstream-aligned version would:

- Keep public buffer layout as close to upstream as possible (`size_t` capacity/off, existing macro behavior).
- Add direction/origin as opt-in metadata without breaking old source users where possible.
- Preserve the old QUIC block encoding behavior or explicitly deprecate it with a safe failure mode.
- Keep allocator hooks narrowly documented as process-global, early-initialization hooks, or wrap them in a struct if future per-context allocation is needed.

## Verification

Commands run:

- `git diff --check`: passed.
- `make -j2 test-fusion.t test-minicrypto.t test-openssl.t`: passed.
- `./test-fusion.t`: passed.
- `./test-minicrypto.t`: passed.
- `./test-openssl.t`: passed.
- `env BINARY_DIR=/home/count0/src/picotls prove --exec '' -v /home/count0/src/picotls/test-openssl.t`: passed.

`make check` was also run once. It failed in `test-openssl.t` subtest 9 during the full five-file run, but the same `test-openssl.t` binary and the same `prove` invocation passed immediately afterward. Treat this as a possible flaky failure unless it reproduces.

## Proposed Merge Plan

1. Commit or stash the current four-file unstaged fusion/doc patch so the upstream merge can be reviewed cleanly.
2. Merge `upstream/master`.
3. Resolve the single `lib/picotls.c` conflict by combining ECH-grease behavior with the fork's buffer-direction argument.
4. Port upstream fusion allocation assertions into the local multivec implementation.
5. Fix the local buffer API issues above, especially the `uint32_t` overflow and removed `ptls_buffer_push_block(..., -1, ...)` behavior.
6. Update `picotlsvs/picotlsvs/picotlsvs.c` and guard Windows CMake target references.
7. Run `git diff --check`, `make check`, and a targeted rerun of `test-openssl.t` if the full suite flakes again.
