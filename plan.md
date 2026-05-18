# Upstream Merge Plan

Date: 2026-05-18

## Objective

Merge canonical upstream `h2o/picotls` through local ref `upstream/master` into this fork while preserving fork-specific packaging, MinGW, buffer allocator, buffer direction, and current fusion multivector work.

The plan incorporates the `RESOLUTION` notes in `review.md`:

- keep `ptls_buffer_t.capacity` and `ptls_buffer_t.off` as `size_t`
- keep direction metadata and allocator hooks
- restore `ptls_buffer_push_block(buf, -1, ...)` / `ptls_buffer__adjust_quic_blocksize`
- convert stale Visual Studio sample buffer initialization calls
- fix allocator hook documentation
- add upstream fusion allocation assertions
- add in-place and overlapping multivector fusion tests
- remove hot-path per-record `malloc(inlen)` from fusion vector encryption
- use the same allocation-failure style as upstream fusion

## Current Inputs

- local branch: `master`
- local head: `600d5ce9c8d4a9f8fbeef7cb892887c4776ced6b`
- upstream ref: `upstream/master`
- upstream head: `7c32032f91449d695b24b82955f20d04d47e6cff`
- merge base: `34d4d6496cec80bc3b56dbdab45f21bd9fbc17aa`
- expected merge conflict: one content conflict in `lib/picotls.c`
- current unstaged product diffs: `include/picotls.h`, `include/picotls/openssl.h`, `lib/fusion.c`, `t/fusion.c`

Planning/report files (`review.md`, `plan.md`) are not product code. Decide before execution whether to keep them on the integration branch, commit them separately, or leave them untracked.

## Phase 1: Prepare A Clean Integration Branch

1. Record the current state:

   ```sh
   git status --short
   git show -s --format='%H %ci %s' HEAD
   git show -s --format='%H %ci %s' upstream/master
   git merge-base HEAD upstream/master
   git rev-list --left-right --count HEAD...upstream/master
   ```

2. Create an integration branch from current `master`:

   ```sh
   git switch -c merge-upstream-2026-05-08
   ```

3. Save current unstaged product work before merging.

   Preferred, for reviewability:

   ```sh
   git add include/picotls.h include/picotls/openssl.h lib/fusion.c t/fusion.c
   git commit -m "wip: local buffer and fusion changes before upstream merge"
   ```

   If the current four-file patch should remain uncommitted, use a named stash instead:

   ```sh
   git stash push -m "local buffer and fusion changes before upstream merge" -- include/picotls.h include/picotls/openssl.h lib/fusion.c t/fusion.c
   ```

4. Keep `review.md` and `plan.md` separate from the product merge unless the branch is intended to carry review artifacts.

## Phase 2: Merge Upstream

1. Confirm `upstream/master` is current enough for this merge:

   ```sh
   git fetch https://github.com/h2o/picotls.git master:refs/remotes/upstream/master
   git show -s --format='%H %ci %s' upstream/master
   ```

2. Merge upstream:

   ```sh
   git merge upstream/master
   ```

3. Resolve the known `lib/picotls.c` conflict in ClientHello PSK identity emission.

   Keep both the fork's direction-aware reserve call and upstream's ECH grease condition:

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

   Also keep upstream's condition for obfuscated ticket age:

   ```c
   if (mode == ENCODE_CH_MODE_OUTER && ech->state != PTLS_ECH_STATE_GREASE) {
       ctx->random_bytes(&age, sizeof(age));
   } else {
       age = obfuscated_ticket_age;
   }
   ```

4. Check for unresolved merge debris and old buffer signatures:

   ```sh
   rg -n '<<<<<<<|=======|>>>>>>>' .
   rg -n 'ptls_buffer_reserve\([^,\n]+,[^,\n]+\)' include lib src t fuzz picotlsvs
   rg -n 'ptls_buffer_reserve_aligned\([^,\n]+,[^,\n]+,[^,\n]+\)' include lib src t fuzz picotlsvs
   ```

5. Build once before deeper local refactoring:

   ```sh
   make -j2 test-fusion.t test-minicrypto.t test-openssl.t
   ```

## Phase 3: Reconcile Buffer API Decisions

Target files:

- `include/picotls.h`
- `lib/picotls.c`
- `t/picotls.c`
- buffer call sites under `lib/`, `t/`, `fuzz/`, `src/`, and `picotlsvs/`

### 3.1 Keep Public Buffer Sizes As `size_t`

Update `ptls_buffer_t`:

```c
typedef struct st_ptls_buffer_t {
    uint8_t *base;
    void *origin;
    size_t capacity;
    size_t off;
    uint8_t is_allocated;
    uint8_t align_bits;
    uint8_t tx;
} ptls_buffer_t;
```

Update buffer prototypes and inline helpers to use `size_t`:

```c
static void ptls_buffer_init(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size, int tx);
static void ptls_buffer_init_rx(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size);
static void ptls_buffer_init_tx(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size);
int ptls_buffer_reserve(ptls_buffer_t *buf, size_t delta, int tx);
int ptls_buffer_reserve_aligned(ptls_buffer_t *buf, size_t delta, uint8_t align_bits, int tx);
extern void *(*ptls_buffer_alloc)(ptls_buffer_t *buf, size_t capacity, uint8_t align_bits, int tx);
```

Update the default allocator implementation and tests to match:

- `buffer_alloc` takes `size_t new_capacity`
- `ptls_buffer_alloc` function pointer takes `size_t capacity`
- `test_buffer_alloc` in `t/picotls.c` takes `size_t new_capacity`
- tracking fields that store capacities remain `size_t`

### 3.2 Remove 32-bit Reserve Arithmetic

Rewrite `ptls_buffer_reserve_aligned` to avoid `uint32_t` addition and `__builtin_clz(uint32_t)` assumptions.

Required checks:

```c
if (delta > SIZE_MAX - buf->off)
    return PTLS_ERROR_NO_MEMORY;
size_t required = buf->off + delta;
```

Capacity growth may use either:

- the previous doubling loop with overflow checks; or
- a branchless next-power-of-two helper rewritten for `size_t` with `__builtin_clzl` / `__builtin_clzll` guarded by `sizeof(size_t)`.

The conservative option is preferable for merge safety:

```c
size_t new_capacity = buf->capacity < 1024 ? 1024 : buf->capacity;
while (new_capacity < required) {
    if (new_capacity > SIZE_MAX / 2) {
        new_capacity = required;
        break;
    }
    new_capacity *= 2;
}
```

Allocator-specific maximums should be enforced by the allocator hook or an optional wrapper around it, not by narrowing the public buffer type.

### 3.3 Restore QUIC Varint Block Support

Restore the declaration:

```c
int ptls_buffer__adjust_quic_blocksize(ptls_buffer_t *buf, size_t body_size);
```

Restore `ptls_buffer_push_block` support for `_capacity == (size_t)-1`:

```c
size_t capacity = (_capacity);
ptls_buffer_pushv((buf), (uint8_t *)"\0\0\0\0\0\0\0", capacity != (size_t)-1 ? capacity : 1);
...
if (capacity != (size_t)-1) {
    ...
} else {
    if ((ret = ptls_buffer__adjust_quic_blocksize((buf), body_size)) != 0)
        goto Exit;
}
```

Restore `ptls_buffer__adjust_quic_blocksize` in `lib/picotls.c`, using the direction on the buffer:

```c
if ((ret = ptls_buffer_reserve(buf, sizelen - 1, buf->tx)) != 0)
    return ret;
```

Restore tests in `t/picotls.c` so `test_quicblock` again exercises:

- `ptls_buffer_push_block(&buf, -1, ...)` for a small body
- a body large enough to require a multi-byte QUIC varint length
- decode through `ptls_decode_block(..., -1, ...)`

### 3.4 Preserve Direction Metadata

Keep:

- `origin`
- `tx`
- `ptls_buffer_init_rx`
- `ptls_buffer_init_tx`
- `buffer_require_direction`
- direction-aware reserve calls in RX and TX paths

After the merge and size restoration, run:

```sh
rg -n 'ptls_buffer_init\([^,\n]+,[^,\n]+,[^,\n]+\)' include lib src t fuzz picotlsvs
rg -n 'ptls_buffer_reserve\([^,\n]+,[^,\n]+\)' include lib src t fuzz picotlsvs
```

Expected outcome:

- no old three-argument `ptls_buffer_init` users outside the helper declaration/definition
- no old two-argument `ptls_buffer_reserve` users
- deliberate uses of four-argument `ptls_buffer_init(..., tx)` are acceptable inside helpers or context-sensitive paths such as HPKE

### 3.5 Fix Visual Studio Sample Calls

Update `picotlsvs/picotlsvs/picotlsvs.c`:

```c
ptls_buffer_init_tx(sendbuf, "", 0);
```

for both stale calls currently equivalent to:

- `handshake_init`
- `handshake_progress`

### 3.6 Fix Allocator Hook Documentation

In `include/picotls.h`, update `ptls_buffer_free` docs:

- remove "returns NULL on failure"
- state that the hook must clear/free resources for an allocated buffer and must not fail
- keep the paired-hook requirement with `ptls_buffer_alloc`

## Phase 4: Reconcile Fusion Multivector Work

Target files:

- `lib/fusion.c`
- `t/fusion.c`
- `include/picotls/fusion.h` after upstream comments merge

### 4.1 Apply Upstream Allocation Assertions

Port upstream assertions into the local tree after merge:

```c
if (inlen + aadlen > ctx->aesgcm->capacity) {
    ctx->aesgcm = ptls_fusion_aesgcm_set_capacity(ctx->aesgcm, inlen + aadlen);
    assert(ctx->aesgcm != NULL && "fusion assumes sufficient amount of memory to be available");
}
```

Apply the same style in:

- `aead_do_encrypt`
- `aead_do_decrypt`
- `aesgcm_setup`
- `non_temporal_setup`

Also keep upstream's CTR assertion wording cleanup.

### 4.2 Remove Per-record `malloc(inlen)` From `aead_do_encrypt_v`

Do not keep the current overlap fallback that calls `malloc(inlen)` inside `aead_do_encrypt_v`.

Preferred implementation:

1. Add reusable scratch storage to `struct aesgcm_context`:

   ```c
   uint8_t *scratch;
   size_t scratch_capacity;
   ```

2. Initialize it to `{NULL, 0}` during setup.

3. Free it in `aesgcm_dispose_crypto`:

   ```c
   if (ctx->scratch != NULL) {
       ptls_clear_memory(ctx->scratch, ctx->scratch_capacity);
       free(ctx->scratch);
   }
   ```

4. Add helper:

   ```c
   static uint8_t *aesgcm_get_scratch(struct aesgcm_context *ctx, size_t required)
   ```

   It grows scratch only when `required > ctx->scratch_capacity`, clears/frees old scratch, and uses upstream's assertion-on-allocation-failure style.

5. In `aead_do_encrypt_v`:

   - compute `inlen` with `size_t` overflow checking
   - fast-path `incnt == 1` to `aead_do_encrypt`
   - detect whether all input ranges can be safely copied/coalesced into `output`
   - if safe, coalesce with `memmove(output + off, input[i].base, input[i].len)` and encrypt from `output`
   - if unsafe overlap exists, coalesce into reusable scratch and encrypt from scratch into `output`
   - clear scratch bytes used after encryption if scratch was used

Unsafe overlap means an input segment intersects `[output, output + inlen)` but is not exactly at its final coalesced position. This is the current detection rule, but the backing storage should be reusable scratch, not a fresh allocation.

Alternative if reusable scratch is considered too much state:

- implement a true vector-aware fusion AES-GCM encryptor that consumes iovecs directly without coalescing; this is more invasive and should not be required for the first merge.

### 4.3 Add Fusion Multivector Tests

Extend `t/fusion.c` with deterministic tests, not only the existing random separate-buffer path.

Add cases for both `ptls_fusion_aes128gcm` and `ptls_fusion_aes256gcm`:

- separate output buffer, three input vectors
- exact in-place contiguous vectors, where `output == input[0].base`
- partially overlapping output/input that forces the scratch fallback
- zero-length vector among non-empty vectors
- input length greater than default fusion capacity to exercise capacity growth and scratch growth together

For each case:

1. encrypt with fusion `ptls_aead_encrypt_v`
2. decrypt with minicrypto and compare plaintext
3. encrypt/decrypt both normal IV and IV96 modes if the surrounding harness already supports it

The current test harness uses randomized data in `test_generated`; keep it, but add named subtests so overlap failures are easy to identify.

### 4.4 Keep OpenSSL Async Documentation Fix

Preserve the unstaged documentation change in `include/picotls/openssl.h`:

```text
ptls_get_async_job(...)->get_fd(...)
```

No code change is expected for this item.

## Phase 5: Build, Install, And Packaging Cleanup

These items were not marked with explicit `RESOLUTION` lines, but they remain low-risk cleanup from `review.md`.

1. Replace open-coded install directory defaults with `GNUInstallDirs`:

   ```cmake
   include(GNUInstallDirs)
   ```

   Then rely on `CMAKE_INSTALL_INCLUDEDIR` and `CMAKE_INSTALL_LIBDIR`.

2. Guard Windows target links:

   ```cmake
   if (TARGET test-fusion.t)
       target_link_libraries(test-fusion.t bcrypt ws2_32)
   endif()
   ```

   Do the same style for any optional target referenced in the `WIN32` block.

3. Keep the current Windows `check` omission unless a separate Windows test runner is added.

4. Keep `PKGBUILD` as local-development packaging unless the branch is explicitly targeting downstream package publication.

## Phase 6: Re-run Merge-wide Static Checks

Run these after all code edits:

```sh
git diff --check
rg -n '<<<<<<<|=======|>>>>>>>' .
rg -n 'ptls_buffer_reserve\([^,\n]+,[^,\n]+\)' include lib src t fuzz picotlsvs
rg -n 'ptls_buffer_init\([^,\n]+,[^,\n]+,[^,\n]+\)' include lib src t fuzz picotlsvs
rg -n 'malloc\(inlen\)' lib/fusion.c
```

Expected results:

- no whitespace errors
- no merge markers
- no old buffer reserve/init call signatures
- no `malloc(inlen)` in `lib/fusion.c`

## Phase 7: Test Matrix

### Required local Linux tests

```sh
make -j2 test-fusion.t test-minicrypto.t test-openssl.t
./test-fusion.t
./test-minicrypto.t
./test-openssl.t
make check
```

If `make check` flakes in `test-openssl.t` again:

```sh
env BINARY_DIR=/home/count0/src/picotls prove --exec '' -v /home/count0/src/picotls/test-openssl.t
```

Record both the failure and rerun result in the merge commit notes.

### Optional targeted configurations

Run if toolchains/dependencies are available:

```sh
cmake -S . -B build-no-fusion -DWITH_FUSION=OFF
cmake --build build-no-fusion
cmake --build build-no-fusion --target test-minicrypto.t test-openssl.t
```

```sh
cmake -S . -B build-install -DCMAKE_INSTALL_PREFIX=/tmp/picotls-install
cmake --build build-install
cmake --install build-install
```

For Windows/MinGW, at minimum verify configure and build:

```sh
cmake -G "MSYS Makefiles" -S . -B build-mingw
cmake --build build-mingw
```

## Phase 8: Review Before Final Commit

Review the final diff by topic:

```sh
git diff --stat upstream/master...HEAD
git diff upstream/master...HEAD -- include/picotls.h lib/picotls.c t/picotls.c
git diff upstream/master...HEAD -- lib/fusion.c t/fusion.c include/picotls/fusion.h
git diff upstream/master...HEAD -- CMakeLists.txt cmake/picotls.pc.in PKGBUILD picotlsvs/picotlsvs/picotlsvs.c
```

Confirm these acceptance criteria:

- upstream security and correctness fixes are present
- `PTLS_MAX_SIGNATURE_ALGORITHMS` is 64
- ECH grease state changes and tests are present
- mbedTLS, bcrypt, ASN.1, libaegis, OpenSSL 3.5, and Brotli fixes are present
- buffer public sizes are `size_t`
- buffer direction/origin hooks are preserved
- QUIC varint block behavior is restored
- Visual Studio sample uses direction-aware buffer initialization
- fusion vector encryption has no per-record heap allocation
- fusion overlap tests pass
- async OpenSSL docs point to `ptls_get_async_job(...)->get_fd(...)`

## Phase 9: Commit Strategy

Prefer small integration commits after the upstream merge commit:

1. Merge upstream:

   ```sh
   git commit
   ```

   Use the default merge commit message, then add a short note:

   ```text
   Resolved local buffer-direction API conflict in ClientHello PSK ECH grease path.
   ```

2. Buffer API compatibility fix:

   ```sh
   git add include/picotls.h lib/picotls.c t/picotls.c picotlsvs/picotlsvs/picotlsvs.c
   git commit -m "restore size_t buffer API and QUIC block support"
   ```

3. Fusion multivector hardening:

   ```sh
   git add lib/fusion.c t/fusion.c include/picotls/fusion.h
   git commit -m "harden fusion multivector encryption"
   ```

4. Build/install cleanup if performed:

   ```sh
   git add CMakeLists.txt cmake/picotls.pc.in PKGBUILD
   git commit -m "clean up install and Windows target handling"
   ```

If the current pre-merge four-file patch was committed as a WIP, either amend/squash it into the topic commits before publishing or leave it only on the private integration branch.

## Rollback And Recovery

Before starting the merge, note the original commit:

```sh
git rev-parse HEAD
```

If the merge becomes unrecoverable before commit:

```sh
git merge --abort
```

If the integration branch gets too noisy after commits, do not reset shared branches. Create a new integration branch from `master` and replay only the reviewed commits with `git cherry-pick`.
