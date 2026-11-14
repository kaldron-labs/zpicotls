/* Immutable fragmented plaintext must produce the same records as contiguous input. */
#include <stdlib.h>
#include <string.h>
#include "zpicotls.h"
#include "zpicotls/openssl.h"
#include "zpicotls/fusion.h"
#include "../deps/picotest/picotest.h"

#ifndef PTLS_HAVE_RECORD_CHUNKS
#error "serial record output is required"
#endif

struct chunk_sink {
    uint8_t *bytes;
    size_t capacity, off, reserved, step, exposed;
    int fail, discarded, finished, reserves, fault, fail_after;
};

static int chunk_reserve(void *arg, size_t size)
{
    struct chunk_sink *ctx = arg;
    ++ctx->reserves;
    if (ctx->fail || ctx->reserves == ctx->fail_after || size > ctx->capacity - ctx->off)
        return PTLS_ERROR_NO_MEMORY;
    ctx->reserved = size;
    return 0;
}

static int chunk_next(void *arg, void **base, size_t *capacity)
{
    struct chunk_sink *ctx = arg;
    *base = ctx->bytes + ctx->off;
    ctx->exposed = *capacity = ctx->reserved < ctx->step ? ctx->reserved : ctx->step;
    if (ctx->fault == 1)
        *capacity = 0;
    return 0;
}

static int chunk_commit(void *arg, size_t length)
{
    struct chunk_sink *ctx = arg;
    if (ctx->fault == 2 || length > ctx->exposed || length > ctx->reserved)
        return PTLS_ERROR_LIBRARY;
    ctx->off += length;
    ctx->reserved -= length;
    ctx->exposed = 0;
    return 0;
}

static int chunk_finish(void *arg)
{
    struct chunk_sink *ctx = arg;
    if (ctx->fault == 3 || ctx->reserved != 0)
        return PTLS_ERROR_LIBRARY;
    ++ctx->finished;
    return 0;
}

static void chunk_discard(void *arg)
{
    struct chunk_sink *ctx = arg;
    ++ctx->discarded;
}

static ptls_record_sink_t make_sink(struct chunk_sink *ctx)
{
    return (ptls_record_sink_t){ctx, chunk_reserve, chunk_next, chunk_commit, chunk_finish, chunk_discard};
}

static size_t alloc_calls;
static void *reject_alloc(ptls_buffer_t *buf, size_t capacity, uint8_t align_bits, int tx)
{
    ++alloc_calls;
    return NULL;
}

static int (*capture_setup)(ptls_aead_context_t *, int, const void *, const void *);
static ptls_aead_context_t *captured_enc, *captured_dec;

static int capture_aead(ptls_aead_context_t *ctx, int enc, const void *key, const void *iv)
{
    int ret = capture_setup(ctx, enc, key, iv);
    if (ret == 0) {
        if (enc)
            captured_enc = ctx;
        else
            captured_dec = ctx;
    }
    return ret;
}

static void (*saved_dec_abort)(ptls_aead_context_t *);
static unsigned dec_abort_calls;
static void count_dec_abort(ptls_aead_context_t *ctx)
{
    ++dec_abort_calls;
    saved_dec_abort(ctx);
}

static int (*saved_end)(ptls_aead_context_t *, void *, size_t, size_t *);
static void *tag_destination;

static int capture_end(ptls_aead_context_t *ctx, void *output, size_t capacity, size_t *written)
{
    tag_destination = output;
    return saved_end(ctx, output, capacity, written);
}

static void unavailable(ptls_t *initial)
{
    ptls_buffer_t state;
    ptls_buffer_init_tx(&state, "", 0);
    ok(ptls_export(initial, &state) == 0);
    struct st_ptls_aead_algorithm_t algo = *ptls_get_cipher(initial)->aead;
    struct st_ptls_cipher_suite_t suite = *ptls_get_cipher(initial);
    capture_setup = algo.setup_crypto;
    algo.setup_crypto = capture_aead;
    suite.aead = &algo;
    ptls_cipher_suite_t *suites[] = {&suite, NULL};
    ptls_context_t ctx = *ptls_get_context(initial);
    ctx.cipher_suites = ctx.tls12_cipher_suites = suites;
    ptls_t *test = NULL, *reference = NULL;
    ok(ptls_import(&ctx, &test, ptls_iovec_init(state.base, state.off)) == 0);
    ptls_aead_context_t *enc = captured_enc;
    ok(ptls_import(ptls_get_context(initial), &reference, ptls_iovec_init(state.base, state.off)) == 0);
    ptls_tx_t *tx = NULL, *ref = NULL;
    ok(ptls_detach_tx(test, &tx) == 0);
    ok(ptls_detach_tx(reference, &ref) == 0);
    uint8_t bytes[256], expected[256];
    struct chunk_sink data = {.bytes = bytes, .capacity = sizeof(bytes), .step = 1};
    ptls_record_sink_t sink = make_sink(&data);
    for (int missing = 0; missing < 3; ++missing) {
        int (*begin)(ptls_aead_context_t *, uint64_t, const void *, size_t) = enc->do_enc_begin;
        int (*chunk)(ptls_aead_context_t *, void *, const void *, size_t, size_t *) = enc->do_enc_chunk;
        int (*end)(ptls_aead_context_t *, void *, size_t, size_t *) = enc->do_enc_end;
        if (missing == 0)
            enc->do_enc_begin = NULL;
        else if (missing == 1)
            enc->do_enc_chunk = NULL;
        else
            enc->do_enc_end = NULL;
        ok(ptls_tx_send_chunks(tx, &sink, "check", 5) == PTLS_ERROR_NOT_AVAILABLE);
        ok(data.reserves == 0 && data.off == 0 && data.discarded == 0);
        uint8_t fallback_bytes[128], reference_bytes[128];
        ptls_buffer_t fallback, reference_buf;
        ptls_buffer_init_tx(&fallback, fallback_bytes, sizeof(fallback_bytes));
        ptls_buffer_init_tx(&reference_buf, reference_bytes, sizeof(reference_bytes));
        ptls_iovec_t spans[3] = {ptls_iovec_init("ch", 2), ptls_iovec_init("eck", 3)};
        ok(ptls_tx_sendv(tx, &fallback, spans, 2) == 0);
        ok(ptls_tx_send(ref, &reference_buf, "check", 5) == 0);
        ok(fallback.off == reference_buf.off && memcmp(fallback.base, reference_buf.base, fallback.off) == 0);
        ptls_buffer_dispose(&fallback);
        ptls_buffer_dispose(&reference_buf);
        enc->do_enc_begin = begin;
        enc->do_enc_chunk = chunk;
        enc->do_enc_end = end;
    }
    /* Contiguous vector output must not enter serial callbacks even when all are installed. */
    saved_end = enc->do_enc_end;
    enc->do_enc_end = capture_end;
    tag_destination = NULL;
    ptls_buffer_t fast, fast_reference;
    ptls_buffer_init_tx(&fast, bytes, sizeof(bytes));
    ptls_buffer_init_tx(&fast_reference, expected, sizeof(expected));
    ptls_iovec_t fragmented[3] = {ptls_iovec_init("ch", 2), ptls_iovec_init("eck", 3)};
    ok(ptls_tx_sendv(tx, &fast, fragmented, 2) == 0);
    ok(tag_destination == NULL);
    ok(ptls_tx_send(ref, &fast_reference, "check", 5) == 0);
    ok(fast.off == fast_reference.off && memcmp(fast.base, fast_reference.base, fast.off) == 0);
    ptls_buffer_dispose(&fast);
    ptls_buffer_dispose(&fast_reference);
    enc->do_enc_end = saved_end;
    saved_end = enc->do_enc_end;
    enc->do_enc_end = capture_end;
    tag_destination = NULL;
    /* One-byte spans force the bounded tag scratch path. */
    ok(ptls_tx_send_chunks(tx, &sink, "check", 5) == 0);
    ok(tag_destination != NULL && tag_destination != bytes + data.off - enc->algo->tag_size);
    enc->do_enc_end = saved_end;
    ptls_buffer_t contiguous;
    ptls_buffer_init_tx(&contiguous, expected, sizeof(expected));
    ok(ptls_tx_send(ref, &contiguous, "check", 5) == 0);
    ok(data.off == contiguous.off && memcmp(bytes, contiguous.base, data.off) == 0);
    data.off = 0;
    data.step = sizeof(bytes);
    contiguous.off = 0;
    tag_destination = NULL;
    enc->do_enc_end = capture_end;
    ok(ptls_tx_send_chunks(tx, &sink, "check", 5) == 0);
    ok(tag_destination == bytes + data.off - enc->algo->tag_size);
    enc->do_enc_end = saved_end;
    ok(ptls_tx_send(ref, &contiguous, "check", 5) == 0);
    ok(data.off == contiguous.off && memcmp(bytes, contiguous.base, data.off) == 0);
    ptls_buffer_dispose(&contiguous);
    for (int trial = 0; trial != 6; ++trial) {
        int fault = 1 + trial % 3;
        ptls_t *broken = NULL;
        ptls_tx_t *broken_tx = NULL;
        ok(ptls_import(ptls_get_context(initial), &broken, ptls_iovec_init(state.base, state.off)) == 0);
        if (trial >= 3 && ptls_get_protocol_version(broken) == PTLS_PROTOCOL_VERSION_TLS13)
            ok(ptls_update_key(broken, 0) == 0);
        ok(ptls_detach_tx(broken, &broken_tx) == 0);
        struct chunk_sink failure = {.bytes = bytes, .capacity = sizeof(bytes), .step = 1, .fault = fault};
        ptls_record_sink_t failing = make_sink(&failure);
        ok(ptls_tx_send_chunks(broken_tx, &failing, "check", 5) == PTLS_ERROR_LIBRARY);
        ok(failure.discarded == 1 && failure.finished == 0);
        failure.fault = 0;
        int reserves = failure.reserves;
        ok(ptls_tx_send_chunks(broken_tx, &failing, "retry", 5) == PTLS_ERROR_LIBRARY);
        ok(ptls_tx_alert_chunks(broken_tx, &failing, 1, 0) == PTLS_ERROR_LIBRARY);
        ok(failure.reserves == reserves);
        ptls_buffer_t retry;
        ptls_buffer_init_tx(&retry, "", 0);
        ok(ptls_tx_send(broken_tx, &retry, "retry", 5) == PTLS_ERROR_LIBRARY && retry.off == 0);
        ptls_buffer_dispose(&retry);
        ptls_tx_free(broken_tx);
        ptls_free(broken);
    }
    ptls_buffer_dispose(&state);
    ptls_tx_free(ref);
    ptls_tx_free(tx);
    ptls_free(reference);
    ptls_free(test);
}

static void pending_record(ptls_t *initial)
{
    ptls_buffer_t state;
    ptls_buffer_init_tx(&state, "", 0);
    ok(ptls_export(initial, &state) == 0);
    ptls_t *test = NULL, *reference = NULL;
    ok(ptls_import(ptls_get_context(initial), &test, ptls_iovec_init(state.base, state.off)) == 0);
    ok(ptls_import(ptls_get_context(initial), &reference, ptls_iovec_init(state.base, state.off)) == 0);
    ok(ptls_update_key(test, 0) == 0);
    ok(ptls_update_key(reference, 0) == 0);
    ptls_tx_t *tx = NULL, *ref = NULL;
    ok(ptls_detach_tx(test, &tx) == 0);
    ok(ptls_detach_tx(reference, &ref) == 0);
    uint8_t input[16384] = {0}, bytes[17000], expected[17000];
    struct chunk_sink data = {.bytes = bytes, .capacity = sizeof(bytes), .step = 1460, .fail = 1};
    ptls_record_sink_t sink = make_sink(&data);
    ok(ptls_tx_send_chunks(tx, &sink, input, sizeof(input)) == PTLS_ERROR_NO_MEMORY);
    ok(data.reserves == 1 && data.discarded == 1 && data.off == 0);
    data.fail = 0;
    ok(ptls_tx_send_chunks(tx, &sink, input, sizeof(input)) == 0);
    ok(data.reserves == 2 && data.finished == 1);
    ptls_buffer_t contiguous;
    ptls_buffer_init_tx(&contiguous, expected, sizeof(expected));
    ok(ptls_tx_send(ref, &contiguous, input, sizeof(input)) == 0);
    ok(data.off == contiguous.off && memcmp(bytes, contiguous.base, data.off) == 0);
    ptls_buffer_dispose(&contiguous);
    ptls_buffer_dispose(&state);
    ptls_tx_free(ref);
    ptls_tx_free(tx);
    ptls_free(reference);
    ptls_free(test);
}

struct plain_sink {
    uint8_t bytes[PTLS_RECEIVE_RECORD_CAPACITY + 2];
    size_t length;
    int reserved, committed, discarded, fail;
};

static int plain_reserve(void *arg, size_t size, void **base, size_t *capacity)
{
    struct plain_sink *s = arg;
    ++s->reserved;
    *base = s->bytes + 1; /* Deliberately unaligned destination, with head/tail guards. */
    *capacity = PTLS_RECEIVE_RECORD_CAPACITY;
    memset(s->bytes, 0xa5, sizeof(s->bytes));
    return s->fail || size > *capacity ? PTLS_ERROR_NO_MEMORY : 0;
}

static int plain_commit(void *arg, size_t length)
{
    struct plain_sink *s = arg;
    ++s->committed;
    s->length += length;
    return 0;
}

static void plain_discard(void *arg)
{
    ++((struct plain_sink *)arg)->discarded;
}

static ptls_plaintext_sink_t plain_callbacks(struct plain_sink *s)
{
    return (ptls_plaintext_sink_t){s, plain_reserve, plain_commit, plain_discard};
}

static void receive_stream_trial(ptls_t *initial, const uint8_t *wire, size_t wire_length,
                                 const uint8_t *expected, size_t expected_length, size_t step)
{
    ptls_buffer_t state;
    ptls_buffer_init_tx(&state, "", 0);
    ok(ptls_export(initial, &state) == 0);
    ptls_t *rx = NULL;
    ok(ptls_import(ptls_get_context(initial), &rx, ptls_iovec_init(state.base, state.off)) == 0);
    struct plain_sink clear = {0};
    ptls_plaintext_sink_t plain = plain_callbacks(&clear);
    uint8_t control[1024];
    struct chunk_sink out = {.bytes = control, .capacity = sizeof(control), .step = 7};
    ptls_record_sink_t sink = make_sink(&out);
    size_t empty = 0;
    ok(ptls_receive_stream(rx, &plain, &sink, NULL, &empty, NULL) == PTLS_ERROR_IN_PROGRESS && empty == 0);
    int good = 1;
    void *(*saved_alloc)(ptls_buffer_t *, size_t, uint8_t, int) = ptls_buffer_alloc;
    ptls_buffer_alloc = reject_alloc;
    alloc_calls = 0;
    for (size_t off = 0; off < wire_length;) {
        size_t n = wire_length - off;
        if (n > step)
            n = step;
        int before = clear.committed;
        int ret = ptls_receive_stream(rx, &plain, &sink, wire + off, &n, NULL);
        good &= (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && n != 0;
        good &= clear.bytes[0] == 0xa5 || clear.reserved == 0;
        if (ret == PTLS_ERROR_IN_PROGRESS)
            good &= clear.committed == before;
        if (!good)
            break;
        off += n;
    }
    ptls_buffer_alloc = saved_alloc;
    ok(alloc_calls == 0);
    ok(good);
    ok(clear.length == expected_length && (expected_length == 0 ||
       memcmp(clear.bytes + 1, expected, expected_length) == 0));
    ok(clear.reserved == 0 || (clear.bytes[0] == 0xa5 && clear.bytes[sizeof(clear.bytes) - 1] == 0xa5));
    ptls_free(rx);
    /* Every truncation region is disposable, and corruption cannot publish provisional output.
     * This trial has a single application record (no preceding KeyUpdate). */
    if (wire_length != 0 && wire[0] == 23 && 5 + (((size_t)wire[3] << 8) | wire[4]) == wire_length) {
        size_t cuts[] = {1, 4, 5, 6, wire_length / 2, wire_length - 1, wire_length};
        for (size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); ++i) {
            ok(ptls_import(ptls_get_context(initial), &rx, ptls_iovec_init(state.base, state.off)) == 0);
            clear = (struct plain_sink){0};
            uint8_t *bad = malloc(wire_length);
            memcpy(bad, wire, wire_length);
            size_t n = cuts[i];
            if (n == wire_length)
                bad[n - 1] ^= 1;
            int ret = ptls_receive_stream(rx, &plain, &sink, bad, &n, NULL);
            ok(ret == (cuts[i] == wire_length ? PTLS_ALERT_BAD_RECORD_MAC : PTLS_ERROR_IN_PROGRESS));
            ok(clear.committed == 0);
            if (cuts[i] == wire_length) {
                size_t retry = wire_length;
                int reserved = clear.reserved;
                ok(ptls_receive_stream(rx, &plain, &sink, bad, &retry, NULL) == PTLS_ERROR_LIBRARY);
                ok(retry == 0 && clear.reserved == reserved);
            }
            ptls_free(rx);
            ok(clear.discarded == (clear.reserved != 0));
            if (clear.reserved != 0 && cuts[i] == wire_length) {
                int cleared = 1;
                for (size_t j = 0; j < expected_length; ++j)
                    cleared &= clear.bytes[j + 1] == 0;
                ok(cleared);
            }
            free(bad);
        }
    }
    if (wire_length != 0 && wire[0] == 23 && 5 + (((size_t)wire[3] << 8) | wire[4]) == wire_length) {
        for (int fault = 0; fault != 3; ++fault) {
            ok(ptls_import(ptls_get_context(initial), &rx, ptls_iovec_init(state.base, state.off)) == 0);
            clear = (struct plain_sink){.fail = fault == 2};
            uint8_t *bad = malloc(wire_length);
            memcpy(bad, wire, wire_length);
            if (fault == 0)
                bad[0] = 0; /* Invalid header type must fail before reservation. */
            else if (fault == 1)
                bad[wire_length / 2] ^= 1; /* Ciphertext corruption. */
            size_t n = wire_length;
            int ret = ptls_receive_stream(rx, &plain, &sink, bad, &n, NULL);
            ok(ret == (fault == 0 ? PTLS_ALERT_DECODE_ERROR :
                       fault == 1 ? PTLS_ALERT_BAD_RECORD_MAC : PTLS_ERROR_NO_MEMORY));
            ok(clear.committed == 0 && clear.reserved == (fault != 0));
            ptls_free(rx);
            free(bad);
        }
    }
    if (expected_length == 16384 && wire_length > 13 && wire[0] == 23 &&
        5 + (((size_t)wire[3] << 8) | wire[4]) == wire_length) {
        for (int fault = 0; fault != 4; ++fault) {
            struct st_ptls_aead_algorithm_t algo = *ptls_get_cipher(initial)->aead;
            struct st_ptls_cipher_suite_t suite = *ptls_get_cipher(initial);
            capture_setup = algo.setup_crypto;
            algo.setup_crypto = capture_aead;
            suite.aead = &algo;
            ptls_cipher_suite_t *suites[] = {&suite, NULL};
            ptls_context_t context = *ptls_get_context(initial);
            context.cipher_suites = context.tls12_cipher_suites = suites;
            ok(ptls_import(&context, &rx, ptls_iovec_init(state.base, state.off)) == 0);
            saved_dec_abort = captured_dec->do_dec_abort;
            captured_dec->do_dec_abort = count_dec_abort;
            dec_abort_calls = 0;
            clear = (struct plain_sink){0};
            size_t prefix = wire_length / 2, n = prefix;
            ok(ptls_receive_stream(rx, &plain, &sink, wire, &n, NULL) == PTLS_ERROR_IN_PROGRESS && n == prefix);
            ok(clear.reserved == 1 && clear.discarded == 0 && clear.committed == 0);
            ptls_plaintext_sink_t invalid = plain;
            invalid.commit = NULL;
            n = 1;
            int ret = ptls_receive_stream(rx, fault == 1 ? NULL : fault == 2 ? &invalid : &plain,
                                         fault == 0 ? NULL : &sink, fault == 3 ? NULL : wire + prefix, &n, NULL);
            ok(ret == PTLS_ERROR_LIBRARY && n == 0);
            ok(clear.discarded == 1 && clear.committed == 0 && dec_abort_calls == 1);
            int cleared = 1;
            for (size_t j = 0; j < prefix - 13; ++j)
                cleared &= clear.bytes[j + 1] == 0;
            ok(cleared && clear.bytes[0] == 0xa5 && clear.bytes[sizeof(clear.bytes) - 1] == 0xa5);
            n = wire_length - prefix;
            ok(ptls_receive_stream(rx, &plain, &sink, wire + prefix, &n, NULL) == PTLS_ERROR_LIBRARY && n == 0);
            ptls_free(rx);
            ok(clear.discarded == 1 && clear.reserved == 1 && dec_abort_calls == 1);
        }
    }
    ptls_buffer_dispose(&state);
}

static void receive_stream_padding(ptls_t *initial)
{
    ptls_cipher_suite_t *suite = ptls_get_cipher(initial);
    uint8_t key[PTLS_MAX_SECRET_SIZE], iv[PTLS_MAX_IV_SIZE];
    uint64_t seq;
    ok(ptls_get_traffic_keys(initial, 0, key, iv, &seq) == 0);
    ptls_aead_context_t *aead = ptls_aead_new_direct(suite->aead, 1, key, iv);
    ok(aead != NULL);
    uint8_t *origin = NULL, *text = NULL;
    ok(posix_memalign((void **)&origin, 64, PTLS_RECEIVE_RECORD_CAPACITY + 128) == 0);
    ok(posix_memalign((void **)&text, 64, PTLS_RECEIVE_RECORD_CAPACITY) == 0);
    uint8_t *wire = origin + 59; /* Leave encrypted payload aligned for one-shot producer variants. */
    for (int mode = 0; mode != 3; ++mode) {
        size_t size = mode == 0 ? 16384 : mode == 1 ? 0 : 16385;
        size_t inner = mode == 0 ? PTLS_RECEIVE_RECORD_CAPACITY - suite->aead->tag_size : size + 1;
        memset(text, 0, inner);
        for (size_t i = 0; i != size; ++i)
            text[i] = (uint8_t)(0x37 + i);
        text[size] = 23;
        size_t encrypted = inner + suite->aead->tag_size;
        wire[0] = 23;
        wire[1] = 3;
        wire[2] = 3;
        wire[3] = encrypted >> 8;
        wire[4] = (uint8_t)encrypted;
        ptls_aead_encrypt(aead, wire + 5, text, inner, seq, wire, 5);
        if (mode != 2) {
            receive_stream_trial(initial, wire, encrypted + 5, text, size, 1);
        } else {
            ptls_buffer_t state;
            ptls_buffer_init_tx(&state, "", 0);
            ok(ptls_export(initial, &state) == 0);
            ptls_t *rx = NULL;
            ok(ptls_import(ptls_get_context(initial), &rx, ptls_iovec_init(state.base, state.off)) == 0);
            struct plain_sink clear = {0};
            ptls_plaintext_sink_t plain = plain_callbacks(&clear);
            uint8_t control[1024];
            struct chunk_sink out = {.bytes = control, .capacity = sizeof(control), .step = 7};
            ptls_record_sink_t sink = make_sink(&out);
            size_t n = encrypted + 5;
            ok(ptls_receive_stream(rx, &plain, &sink, wire, &n, NULL) == PTLS_ALERT_RECORD_OVERFLOW);
            ok(clear.committed == 0 && clear.discarded == 1);
            ptls_free(rx);
            ptls_buffer_dispose(&state);
        }
    }
    ptls_aead_free(aead);
    ptls_clear_memory(key, sizeof(key));
    free(text);
    free(origin);
}

static void records(ptls_t *client, ptls_t *baseline, ptls_t *server, int tls13, int chunks)
{
    if (chunks) {
        if (tls13) {
            ok(ptls_update_key(client, 0) == 0);
            ok(ptls_update_key(baseline, 0) == 0);
        }
    }
    ptls_tx_t *vector_tx = NULL, *scalar_tx = NULL;
    ok(ptls_detach_tx(client, &vector_tx) == 0);
    ok(ptls_detach_tx(baseline, &scalar_tx) == 0);
    if (vector_tx == NULL || scalar_tx == NULL)
        goto Exit;

    const size_t maximum = 16384; /* TLS plaintext record limit. */
    size_t capacity = 2 * (maximum + ptls_tx_get_record_overhead(vector_tx));
    uint8_t *source = malloc(maximum + 1), *wire = NULL, *reference = NULL, *clear = malloc(capacity);
    ok(posix_memalign((void **)&wire, 64, capacity + 1) == 0);
    ok(posix_memalign((void **)&reference, 64, capacity + 1) == 0);
    for (size_t i = 0; i <= maximum; ++i)
        source[i] = (uint8_t)(0x37 + i);

    ptls_buffer_t output;
    ptls_buffer_init_tx(&output, wire, capacity);
    output.origin = wire;
    output.align_bits = ptls_tx_get_cipher(vector_tx)->aead->align_bits;
    ptls_iovec_t oversized[] = {ptls_iovec_init(source, maximum), ptls_iovec_init(source + maximum, 1), {NULL, 0}};
    ok(ptls_tx_sendv(vector_tx, &output, oversized, 2) == PTLS_ERROR_LIBRARY);
    ok(output.off == 0 && output.base == wire);
    ok(ptls_tx_sendv(NULL, &output, NULL, 0) == PTLS_ERROR_NOT_AVAILABLE);

    /* Odd seven-byte fragments cross AEAD block boundaries, including the full record. */
    size_t lengths[] = {0, 1, 17, maximum, 17};
    size_t trials = chunks ? 40 : sizeof(lengths) / sizeof(lengths[0]);
    for (size_t trial = 0; trial != trials; ++trial) {
        size_t length = trial < 5 ? lengths[trial] : trial == 5 ? maximum : 257;
        size_t count = (length + 6) / 7;
        ptls_iovec_t *spans = calloc(count + 1, sizeof(*spans));
        for (size_t i = 0, offset = 0; i != count; ++i) {
            size_t n = length - offset;
            if (n > 7)
                n = 7;
            spans[i] = ptls_iovec_init(source + offset, n);
            offset += n;
        }
        ptls_buffer_t scalar;
        ptls_buffer_init_tx(&output, wire, capacity);
        ptls_buffer_init_tx(&scalar, reference, capacity);
        output.origin = wire;
        scalar.origin = reference;
        output.align_bits = scalar.align_bits = ptls_tx_get_cipher(vector_tx)->aead->align_bits;
        /* Fuzz builds leave dummy authentication tags unwritten. */
        memset(wire, 0, capacity);
        memset(reference, 0, capacity);
        wire[capacity] = reference[capacity] = 0xa5;
        int update = tls13 && trial == sizeof(lengths) / sizeof(lengths[0]) - 1;
        struct chunk_sink chunks_ctx = {
            .bytes = wire, .capacity = capacity, .step = trial < 5 ? trial + 1 : trial < 38 ? trial - 4 : 1460};
        ptls_record_sink_t sink = make_sink(&chunks_ctx);
        if (update) {
            if (chunks)
                ok(ptls_tx_key_chunks(vector_tx, &sink, 0) == 0);
            else
                ok(ptls_tx_update_key(vector_tx, &output, 0) == 0);
            ok(ptls_tx_update_key(scalar_tx, &scalar, 0) == 0);
        }
        void *(*saved_alloc)(ptls_buffer_t *, size_t, uint8_t, int) = ptls_buffer_alloc;
        alloc_calls = 0;
        ptls_buffer_alloc = reject_alloc;
        int ret;
        if (chunks) {
            /* Rejected reservation must leave all traffic key and sequence state untouched. */
            chunks_ctx.fail = 1;
            size_t before = chunks_ctx.off;
            ret = ptls_tx_send_chunks(vector_tx, &sink, source, length);
            int pending = tls13 && trial == 0;
            ok(ret == (length != 0 || pending ? PTLS_ERROR_NO_MEMORY : 0));
            ok(chunks_ctx.off == before && chunks_ctx.discarded == (length != 0 || pending));
            chunks_ctx.fail = 0;
            ret = ptls_tx_send_chunks(vector_tx, &sink, source, length);
            output.off = chunks_ctx.off;
        } else {
            ret = ptls_tx_sendv(vector_tx, &output, spans, count);
        }
        ptls_buffer_alloc = saved_alloc;
        ok(ret == 0);
        ok(alloc_calls == 0);
        ok(output.base == wire && output.origin == wire && !output.is_allocated);
        ok(ptls_tx_send(scalar_tx, &scalar, source, length) == 0);
        ok(output.off == scalar.off && memcmp(output.base, scalar.base, output.off) == 0);
        ok(wire[capacity] == 0xa5 && reference[capacity] == 0xa5);
        size_t record_count = 0;
        for (size_t offset = 0; offset < output.off; ++record_count) {
            size_t n = 5 + ((size_t)wire[offset + 3] << 8) + wire[offset + 4];
            ok(n <= output.off - offset);
            offset += n;
        }
        ok(record_count == (length != 0) + update + (chunks && tls13 && trial == 0));
        int unchanged = 1;
        for (size_t i = 0; i <= maximum; ++i)
            unchanged &= source[i] == (uint8_t)(0x37 + i);
        ok(unchanged);
        receive_stream_trial(server, output.base, output.off, source, length,
                             trial < 5 ? 1 : trial == 5 ? 1460 : trial - 4);
        ptls_buffer_t plain;
        ptls_buffer_init_rx(&plain, clear, capacity);
        for (size_t consumed = 0; consumed < output.off;) {
            size_t n = output.off - consumed;
            ret = ptls_receive(server, &plain, output.base + consumed, &n);
            ok(ret == 0 && n != 0);
            if (ret != 0 || n == 0)
                break;
            consumed += n;
        }
        ok(plain.off == length && memcmp(plain.base, source, length) == 0);
        ptls_buffer_dispose(&plain);
        ptls_buffer_dispose(&scalar);
        ptls_buffer_dispose(&output);
        free(spans);
    }
    if (chunks) {
        struct chunk_sink alert = {.bytes = wire, .capacity = capacity, .step = 1};
        ptls_record_sink_t sink = make_sink(&alert);
        ptls_buffer_t scalar;
        ptls_buffer_init_tx(&scalar, reference, capacity);
        ok(ptls_tx_alert_chunks(vector_tx, &sink, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY) == 0);
        ok(ptls_tx_send_alert(scalar_tx, &scalar, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY) == 0);
        ok(alert.off == scalar.off && memcmp(wire, reference, alert.off) == 0);
        ptls_buffer_t plain;
        ptls_buffer_init_rx(&plain, clear, capacity);
        size_t consumed = alert.off;
        ok(ptls_recv_chunks(server, &plain, &sink, wire, &consumed) ==
            PTLS_ERROR_CLASS_PEER_ALERT + PTLS_ALERT_CLOSE_NOTIFY);
        ok(consumed == alert.off && plain.off == 0);
        ptls_buffer_dispose(&plain);
        ptls_buffer_dispose(&scalar);
    }
    free(clear);
    free(reference);
    free(wire);
    free(source);
Exit:
    ptls_tx_free(vector_tx);
    ptls_tx_free(scalar_tx);
}

static void flight_failures(ptls_context_t *ctx, const void *input, size_t length)
{
    uint8_t wire[65536];
    struct chunk_sink output = {.bytes = wire, .capacity = sizeof(wire), .step = 3};
    ptls_record_sink_t sink = make_sink(&output);
    ptls_t *server = ptls_new(ctx, 1);
    size_t consumed = length;
    int ret = ptls_handshake_chunks(server, &sink, input, &consumed, NULL);
    ok(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS);
    ok(output.reserves > 1 && output.finished == output.reserves && output.discarded == 0);
    int records = output.reserves;
    ptls_free(server);
    uint8_t *tls12 = malloc(length);
    memcpy(tls12, input, length);
    int found = 0;
    const uint8_t versions[] = {0, 43 /* supported_versions */, 0, 3, 2, 3, 4};
    for (size_t off = 0; off + sizeof(versions) <= length; ++off) {
        if (memcmp(tls12 + off, versions, sizeof(versions)) == 0) {
            tls12[off + sizeof(versions) - 1] = 3;
            found = 1;
            break;
        }
    }
    ok(found);
    output = (struct chunk_sink){.bytes = wire, .capacity = sizeof(wire), .step = 3};
    server = ptls_new(ctx, 1);
    consumed = length;
    ok(ptls_handshake_chunks(server, &sink, tls12, &consumed, NULL) == PTLS_ALERT_PROTOCOL_VERSION);
    ok(output.finished == 1 && output.discarded == 0 && output.off == 7);
    ok(wire[0] == 21 /* alert */ && wire[5] == PTLS_ALERT_LEVEL_FATAL && wire[6] == PTLS_ALERT_PROTOCOL_VERSION);
    ptls_free(server);
    free(tls12);
    for (int fail_at = 1; fail_at <= records; ++fail_at) {
        output = (struct chunk_sink){.bytes = wire, .capacity = sizeof(wire), .step = 3, .fail_after = fail_at};
        server = ptls_new(ctx, 1);
        consumed = length;
        ok(ptls_handshake_chunks(server, &sink, input, &consumed, NULL) == PTLS_ERROR_NO_MEMORY);
        ok(output.discarded == 1 && output.finished == fail_at - 1 && output.reserves == fail_at);
        /* Every retained prefix ends at a complete-record boundary. The failing record wrote no bytes. */
        size_t offset = 0;
        for (int record = 0; record < output.finished; ++record) {
            ok(output.off - offset >= 5);
            offset += 5 + ((size_t)wire[offset + 3] << 8) + wire[offset + 4];
            ok(offset <= output.off);
        }
        ok(offset == output.off);
        ptls_free(server);
    }
}

static int handshake(ptls_t *tls, ptls_buffer_t *buf, const void *input, size_t *length, int chunks)
{
    if (!chunks)
        return ptls_handshake(tls, buf, input, length, NULL);
    if (ptls_buffer_reserve_aligned(buf, 65536, 0, 1) != 0)
        return PTLS_ERROR_NO_MEMORY;
    struct chunk_sink ctx = {.bytes = buf->base + buf->off, .capacity = buf->capacity - buf->off, .step = 3};
    ptls_record_sink_t sink = make_sink(&ctx);
    int ret = ptls_handshake_chunks(tls, &sink, input, length, NULL);
    buf->off += ctx.off;
    ok(ctx.discarded == 0);
    ok(ctx.finished == ctx.reserves);
    return ret;
}

static void tls13(int mode)
{
    struct st_ptls_cipher_suite_t suite = mode & 8 ? ptls_openssl_aes256gcmsha384 : ptls_openssl_aes128gcmsha256;
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    if (mode & 4)
        suite = ptls_openssl_chacha20poly1305sha256;
#endif
    if (mode & 1) {
        if (mode & 16)
            suite.aead = mode & 8 ? &ptls_non_temporal_aes256gcm : &ptls_non_temporal_aes128gcm;
        else
            suite.aead = mode & 8 ? &ptls_fusion_aes256gcm : &ptls_fusion_aes128gcm;
    }
    ptls_cipher_suite_t *suites[] = {&suite, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges,
                          .cipher_suites = suites};
    ctx.pre_shared_key.identity = ptls_iovec_init("vector", 6);
    ctx.pre_shared_key.secret = ptls_iovec_init("immutable fragments", 19);
    ctx.pre_shared_key.hash = suite.hash;
    ptls_t *client = ptls_new(&ctx, 0), *server = ptls_new(&ctx, 1), *baseline = NULL;
    ptls_buffer_t cbuf, sbuf, exported;
    ptls_buffer_init_tx(&cbuf, "", 0);
    ptls_buffer_init_tx(&sbuf, "", 0);
    ptls_buffer_init_tx(&exported, "", 0);
    ok(handshake(client, &cbuf, NULL, NULL, !!(mode & 2)) == PTLS_ERROR_IN_PROGRESS);
    if (mode & 2)
        flight_failures(&ctx, cbuf.base, cbuf.off);
    size_t consumed = cbuf.off;
    int ret = handshake(server, &sbuf, cbuf.base, &consumed, !!(mode & 2));
    ok(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS);
    ok(consumed == cbuf.off);
    cbuf.off = 0;
    consumed = sbuf.off;
    ok(handshake(client, &cbuf, sbuf.base, &consumed, !!(mode & 2)) == 0);
    ok(consumed == sbuf.off);
    consumed = cbuf.off;
    ok(handshake(server, &sbuf, cbuf.base, &consumed, !!(mode & 2)) == 0);
    ok(consumed == cbuf.off);
    receive_stream_padding(server);
    if (mode & 2) {
        unavailable(server);
        pending_record(server);
    }
    ok(ptls_export(server, &exported) == 0);
    /* Reverse this server snapshot to make a second client transmitter. This keeps the
     * real server exportable for fresh receive trials at each record sequence. */
    exported.base[2] = 0;
    size_t keyoff = 8 + PTLS_HELLO_RANDOM_SIZE;
    keyoff += 2 + (((size_t)exported.base[keyoff] << 8) | exported.base[keyoff + 1]);
    keyoff += 2 + (((size_t)exported.base[keyoff] << 8) | exported.base[keyoff + 1]);
    keyoff += 2; /* Version-specific state block. */
    size_t secret_size = suite.hash->digest_size + 8;
    uint8_t saved[PTLS_MAX_DIGEST_SIZE + 8];
    memcpy(saved, exported.base + keyoff, secret_size);
    memcpy(exported.base + keyoff, exported.base + keyoff + secret_size, secret_size);
    memcpy(exported.base + keyoff + secret_size, saved, secret_size);
    ok(ptls_import(&ctx, &baseline, ptls_iovec_init(exported.base, exported.off)) == 0);
    if (baseline != NULL)
        records(client, baseline, server, 1, !!(mode & 2));
    ptls_buffer_dispose(&exported);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&cbuf);
    if (baseline != NULL)
        ptls_free(baseline);
    ptls_free(server);
    ptls_free(client);
}

static ptls_t *import_tls12(ptls_context_t *ctx, ptls_cipher_suite_t *cipher, int server)
{
    uint8_t master_secret[PTLS_TLS12_MASTER_SECRET_SIZE], randoms[PTLS_HELLO_RANDOM_SIZE * 2];
    for (size_t i = 0; i != sizeof(master_secret); ++i)
        master_secret[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i != sizeof(randoms); ++i)
        randoms[i] = (uint8_t)(0x80 + i);
    ptls_buffer_t params;
    ptls_buffer_init_tx(&params, "", 0);
    ptls_t *tls = NULL;
    int ret = ptls_build_tls12_export_params(ctx, &params, server, 0, cipher, master_secret, randoms, 1, "localhost",
                                            ptls_iovec_init(NULL, 0));
    if (ret == 0)
        ret = ptls_import(ctx, &tls, ptls_iovec_init(params.base, params.off));
    ptls_buffer_dispose(&params);
    return ret == 0 ? tls : NULL;
}

static void tls12(ptls_cipher_suite_t *cipher, int chunks)
{
    ptls_cipher_suite_t *suites[] = {cipher, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes, .get_time = &ptls_get_time, .tls12_cipher_suites = suites};
    ptls_t *client = import_tls12(&ctx, cipher, 0), *baseline = import_tls12(&ctx, cipher, 0),
           *server = import_tls12(&ctx, cipher, 1);
    ok(client != NULL && baseline != NULL && server != NULL);
    if (client != NULL && baseline != NULL && server != NULL)
        records(client, baseline, server, 0, chunks);
    ptls_free(server);
    ptls_free(baseline);
    ptls_free(client);
}

static int missing_serial, capability_setups;

static int incomplete_tls12(ptls_aead_context_t *ctx, int enc, const void *key, const void *iv)
{
    ++capability_setups;
    int ret = ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256.aead->setup_crypto(ctx, enc, key, iv);
    if (ret == 0 && enc) {
        if (missing_serial == 0)
            ctx->do_enc_begin = NULL;
        else if (missing_serial == 1)
            ctx->do_enc_chunk = NULL;
        else
            ctx->do_enc_end = NULL;
    }
    return ret;
}

static void unavailable_tls12_config(void)
{
    struct st_ptls_aead_algorithm_t aead = *ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256.aead;
    struct st_ptls_cipher_suite_t suite = ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256;
    aead.setup_crypto = incomplete_tls12;
    aead.serial_encrypt = 0;
    suite.aead = &aead;
    ptls_cipher_suite_t *tls13[] = {&ptls_openssl_aes128gcmsha256, NULL}, *tls12[] = {&suite, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes, .get_time = &ptls_get_time,
                         .key_exchanges = ptls_openssl_key_exchanges, .cipher_suites = tls13, .tls12_cipher_suites = tls12};
    for (missing_serial = 0; missing_serial < 3; ++missing_serial) {
        ptls_t *tls = ptls_new(&ctx, 0);
        uint8_t bytes[4096];
        struct chunk_sink output = {.bytes = bytes, .capacity = sizeof(bytes), .step = sizeof(bytes)};
        ptls_record_sink_t sink = make_sink(&output);
        capability_setups = 0;
        int ret = ptls_handshake_chunks(tls, &sink, NULL, NULL, NULL);
        ok(capability_setups == 0);
        ok(ret == PTLS_ERROR_NOT_AVAILABLE);
        ok(output.reserves == 0 && output.off == 0 && output.discarded == 0);
        if (ret == PTLS_ERROR_NOT_AVAILABLE) {
            ptls_buffer_t contiguous;
            ptls_buffer_init_tx(&contiguous, bytes, sizeof(bytes));
            /* Admission did not consume ClientHello or invalidate the contiguous backend. */
            ok(ptls_handshake(tls, &contiguous, NULL, NULL, NULL) == PTLS_ERROR_IN_PROGRESS);
            ok(contiguous.off > 5 && contiguous.base[0] == 22 /* handshake */);
            ptls_buffer_dispose(&contiguous);
        }
        ptls_free(tls);
    }
}

static int incomplete_receive(ptls_aead_context_t *ctx, int enc, const void *key, const void *iv)
{
    ++capability_setups;
    int ret = ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256.aead->setup_crypto(ctx, enc, key, iv);
    if (ret == 0 && !enc) {
        switch (missing_serial) {
        case 0: ctx->do_dec_begin = NULL; break;
        case 1: ctx->do_dec_chunk = NULL; break;
        case 2: ctx->do_dec_end = NULL; break;
        case 3: ctx->do_dec_abort = NULL; break;
        }
    }
    return ret;
}

static void unavailable_receive_config(void)
{
    struct st_ptls_aead_algorithm_t aead = *ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256.aead;
    struct st_ptls_cipher_suite_t suite = ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256;
    aead.setup_crypto = incomplete_receive;
    aead.serial_decrypt = 0;
    suite.aead = &aead;
    ptls_cipher_suite_t *tls13[] = {&ptls_openssl_aes128gcmsha256, NULL}, *tls12[] = {&suite, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes, .get_time = &ptls_get_time,
                         .key_exchanges = ptls_openssl_key_exchanges, .cipher_suites = tls13, .tls12_cipher_suites = tls12};
    for (missing_serial = 0; missing_serial != 4; ++missing_serial) {
        ptls_t *tls = ptls_new(&ctx, 0);
        capability_setups = 0;
        ok(ptls_receive_stream_check(tls) == PTLS_ERROR_NOT_AVAILABLE);
        ok(capability_setups == 0);
        ptls_free(tls);
    }
}

int main(void)
{
    subtest("tls12-unsupported-config", unavailable_tls12_config);
    subtest("receive-unsupported-config", unavailable_receive_config);
    subtest("tls13-openssl-vectors", tls13, 0);
    subtest("tls13-openssl-chunks", tls13, 2);
    subtest("tls13-openssl-aes256-chunks", tls13, 10);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    subtest("tls13-openssl-chacha-chunks", tls13, 6);
#endif
    if (ptls_fusion_is_supported_by_cpu()) {
        subtest("tls13-fusion-vectors", tls13, 1);
        subtest("tls13-fusion-chunks", tls13, 3);
        subtest("tls13-fusion-aes256-chunks", tls13, 11);
        subtest("tls13-fusion-nt128-chunks", tls13, 19);
        subtest("tls13-fusion-nt256-chunks", tls13, 27);
        struct st_ptls_cipher_suite_t nt128 = ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256;
        struct st_ptls_cipher_suite_t nt256 = ptls_openssl_tls12_ecdhe_rsa_aes256gcmsha384;
        nt128.aead = &ptls_non_temporal_aes128gcm;
        nt256.aead = &ptls_non_temporal_aes256gcm;
        subtest("tls12-fusion-nt128-chunks", tls12, &nt128, 1);
        subtest("tls12-fusion-nt256-chunks", tls12, &nt256, 1);
    }
    else
        note("skipping Fusion vectors: CPU lacks required instructions");
    subtest("tls12-explicit-iv-vectors", tls12, &ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256, 0);
    subtest("tls12-explicit-iv-chunks", tls12, &ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256, 1);
    subtest("tls12-openssl-aes256-chunks", tls12, &ptls_openssl_tls12_ecdhe_rsa_aes256gcmsha384, 1);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    subtest("tls12-implicit-iv-vectors", tls12, &ptls_openssl_tls12_ecdhe_rsa_chacha20poly1305sha256, 0);
    subtest("tls12-implicit-iv-chunks", tls12, &ptls_openssl_tls12_ecdhe_rsa_chacha20poly1305sha256, 1);
#endif
    return done_testing();
}
