# Size-optimized version of Blake2s

Adapted from the [reference](https://github.com/BLAKE2/BLAKE2) implementation.

The API uses stream orientation so that RAM-constrained systems can handle long messages.

## Speed and size

The compression function keeps its state in local variables (so a
compiler holds it in registers), and `b2s_puts` compresses whole 64-byte
blocks straight from its input instead of byte by byte. Hashing 4 KB, keyed,
counted in an RV32IMC emulator (clang `-Os`, instructions retired):

| Build | Instructions | Code (RV32, `-Os`) |
|---|---|---|
| The reference-style code this replaced | 474,589 | 1.5 KB |
| Default: the rounds as a loop | 182,671 | 2.2 KB |
| `-DBLAKE2S_UNROLL`: every round written out | 147,506 | 6.7 KB |

`b2s_putc` still takes one byte at a time, for streams; both give the same
hashes, and `make test` checks both builds.

## API

```C
/** Initialization with the full RFC 7693 parameter set
 * @param S        Hash state
 * @param hsize    Hash length in bytes, 1 to 32
 * @param key      Key, or NULL for an unkeyed hash
 * @param keylen   Key length in bytes, 0 (unkeyed) to 32
 * @param salt     8-byte salt, or NULL for zeros
 * @param personal 8-byte personalization, or NULL for zeros
 * @return         Hash length in bytes (0 if a parameter is bogus)
 */
int b2s_init(blake2s_state *S, int hsize, const uint8_t *key, int keylen,
             const uint8_t *salt, const uint8_t *personal);

/** Keyed hash (MAC) initialization, kept for existing users
 * @param ctx   HMAC context
 * @param key   Key, 32 bytes
 * @param hsize Expected hash length in bytes
 * @param ctr   64-bit counter, may be 0 (see below)
 * @return      Actual hash length in bytes (0 if bogus)
 */
int b2s_hmac_init(blake2s_state *S, const uint8_t *key, int hsize, uint64_t ctr);

/** HMAC append byte
 * @param ctx   HMAC context
 * @param c     Byte to add to HMAC
 */
void b2s_hmac_putc(blake2s_state *S, uint8_t c);

/** HMAC finish
 * @param ctx   HMAC context
 * @param out   Output hash
 * @return      0, or -1 if the hash was already finished
 */
int b2s_hmac_final(blake2s_state *S, uint8_t *out);
```

`b2s_hmac_puts` appends a byte array. The append and finish functions work
after either init; `b2s_putc`, `b2s_puts` and `b2s_final` are the same
functions under names that read better for an unkeyed hash.

`b2s_init` gives the same hashes as Python's
`hashlib.blake2s(data, digest_size=hsize, key=key, salt=salt, person=personal)`,
so tools on a PC can check or make them without this code:

| Use | Call | Python |
|---|---|---|
| Plain hash | `b2s_init(S, 32, NULL, 0, NULL, NULL)` | `blake2s(data)` |
| Keyed hash (MAC) | `b2s_init(S, 32, key, 32, NULL, NULL)` | `blake2s(data, key=key)` |
| MAC with a counter | `b2s_init(S, 32, key, 32, ctr_le, NULL)` | `blake2s(data, key=key, salt=ctr.to_bytes(8, 'little'))` |
| Separate purposes | `b2s_init(S, 32, key, 32, NULL, (const uint8_t *)"LFblkMAC")` | `blake2s(data, key=key, person=b'LFblkMAC')` |

Put a counter or nonce in `salt` and a purpose label in `personal`, so that
hashes made for different purposes with the same key can't stand in for each
other.

`b2s_hmac_init(S, key, hsize, 0)` is `b2s_init(S, hsize, key, 32, NULL, NULL)`.
A nonzero `ctr` is XORed into the hash's internal byte counter. That still
makes a different MAC for each counter value, and existing users get the same
results as before, but standard BLAKE2s tools can't reproduce it; new code
should use the salt instead.

The `_g` variants take the state as `size_t *` for callers that keep it in a
generic buffer.

## Tests

`make test` builds and runs `test.c`: the reference keyed KAT
(`blake2-kat.h`), streamed in pieces of every size, and the vectors in
`vectors.h` (unkeyed hashes, keys of 1 to 32 bytes, salt, personalization,
short digests), which `make vectors` regenerates from Python's `hashlib`.
