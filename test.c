/* Blake2s tests
*/
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "./src/blake2s.h"
#include "blake2-kat.h"
#include "vectors.h"

/* b2s_hmac_init with a nonzero ctr, as computed before b2s_init was added:
   key bytes 0..31, message bytes 0, 1, 2, ... */
static const struct { uint64_t ctr; int len; const char *hex; } ctr_vectors[] = {
  {0x1ull,0,"c40b3a10eea9f4e6e07242c5279b0672087b6d94579df05f9e94455ae3e0079c"},
  {0x1ull,5,"cd7e1c0b04b95467b6f64fd84ea7480154703ed5d27c11bae9cf0ef275424afd"},
  {0x1ull,64,"6e96627adc91b4f71cafabb528dfd4a10045e84c917c631bdff338120496c08e"},
  {0x1ull,200,"345cc3aa7671bb1f8719f6f05d70766209f0d680d76ec85b4fe451088b68aaca"},
  {0x123456789abcdefull,0,"8a3de9907247867ea9a3cec4d43157b5a517327c3b86cd17de7269d1967bf5e6"},
  {0x123456789abcdefull,5,"837a59ee5e48453329b6d7ba2a94224b7fd6cb99c317a262c1b06eb792fcccc1"},
  {0x123456789abcdefull,64,"9c947f1e089370e4a9659f5f1c81813f6a5d6193dd3a6482a4e8ca3dcf1254dc"},
  {0x123456789abcdefull,200,"9ac0dfb03ed7d5d5ffa79b149c73ad3e56a6aecf0e5abb7f11de42f9bf29771f"},
};

static int hexeq( const uint8_t *h, const char *hex )
{
  for( int i = 0; i < 32; ++i ) {
    unsigned x;
    if( sscanf( hex + 2 * i, "%2x", &x ) != 1 || x != h[i] ) return 0;
  }
  return 1;
}

/* b2s_init against hashlib, the parameter checks, and b2s_hmac_init's
   ctr compatibility. Returns 0 if all pass. */
static int test_init( const uint8_t *buf )
{
  uint8_t key[BLAKE2S_KEYBYTES], hash[BLAKE2S_OUTBYTES], hash2[BLAKE2S_OUTBYTES];
  blake2s_state S;
  int i, n = (int)( sizeof b2s_vectors / sizeof b2s_vectors[0] );

  for( i = 0; i < BLAKE2S_KEYBYTES; ++i ) key[i] = ( uint8_t )i;

  for( i = 0; i < n; ++i ) {
    const b2s_vector *v = &b2s_vectors[i];
    if( b2s_init( &S, v->hsize, v->keylen ? key : NULL, v->keylen,
                  ( const uint8_t * )v->salt, ( const uint8_t * )v->personal ) != v->hsize ) {
      printf( "b2s_init refused vector %d\n", i );
      return -1;
    }
    for( int j = 0; j < v->len; ++j ) b2s_putc( &S, ( uint8_t )j );
    if( b2s_final( &S, hash ) != 0 || memcmp( hash, v->hash, v->hsize ) ) {
      printf( "vector %d (hsize %d, keylen %d, len %d) doesn't match hashlib\n",
              i, v->hsize, v->keylen, v->len );
      return -1;
    }
  }

  /* bogus parameters */
  if( b2s_init( &S, 0, NULL, 0, NULL, NULL ) || b2s_init( &S, 33, NULL, 0, NULL, NULL )
   || b2s_init( &S, 32, key, 33, NULL, NULL ) || b2s_init( &S, 32, NULL, 16, NULL, NULL ) ) {
    puts( "b2s_init accepted a bogus parameter" );
    return -1;
  }

  /* b2s_hmac_init with ctr 0 is b2s_init with a 32-byte key */
  b2s_hmac_init( &S, key, 32, 0 );
  b2s_hmac_puts( &S, buf, 100 );
  b2s_hmac_final( &S, hash );
  b2s_init( &S, 32, key, 32, NULL, NULL );
  b2s_puts( &S, buf, 100 );
  b2s_final( &S, hash2 );
  if( memcmp( hash, hash2, 32 ) ) {
    puts( "b2s_hmac_init with ctr 0 differs from b2s_init" );
    return -1;
  }

  /* b2s_hmac_init with a nonzero ctr gives what it always did */
  for( i = 0; i < (int)( sizeof ctr_vectors / sizeof ctr_vectors[0] ); ++i ) {
    b2s_hmac_init( &S, key, 32, ctr_vectors[i].ctr );
    b2s_hmac_puts( &S, buf, ctr_vectors[i].len );
    b2s_hmac_final( &S, hash );
    if( !hexeq( hash, ctr_vectors[i].hex ) ) {
      printf( "b2s_hmac_init ctr vector %d changed\n", i );
      return -1;
    }
  }
  printf( "%d hashlib vectors ok\n", n );
  return 0;
}

static int blake2s( void *out, int outlen, const void *in, int inlen, const void *key )
{
  blake2s_state S[1];

  /* Verify parameters */
  if ( NULL == in && inlen > 0 ) return -1;

  if ( NULL == out ) return -1;

  if( !outlen || outlen > BLAKE2S_OUTBYTES ) return -1;

  if( b2s_hmac_init( S, key, outlen, 0 ) < 0 ) return -1;

  b2s_hmac_puts( S, ( const uint8_t * )in, inlen );
  b2s_hmac_final( S, out );
  return 0;
}

int main( void )
{
  uint8_t key[BLAKE2S_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  uint8_t hash[BLAKE2S_OUTBYTES];
  int i, step;

  for( i = 0; i < BLAKE2S_KEYBYTES; ++i ) key[i] = ( uint8_t )i;

  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i ) buf[i] = ( uint8_t )i;

  /* Test simple API */
  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
  {
    blake2s( hash, BLAKE2S_OUTBYTES, buf, i, key );

    if( 0 != memcmp( hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES ) )
    {
      goto fail;
    }
  }

  /* Test streaming API, in pieces smaller than a block and bigger (puts
     compresses whole blocks straight from its input) */
  for(step = 1; step < 3 * BLAKE2S_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      uint8_t hash[BLAKE2S_OUTBYTES];
      blake2s_state S;
      uint8_t * p = buf;
      int mlen = i;
      int err = 0;

      if( (err = b2s_hmac_init(&S, key, BLAKE2S_OUTBYTES, 0)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = b2s_hmac_puts(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = b2s_hmac_puts(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = b2s_hmac_final(&S, hash)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
        goto fail;
      }
    }
  }

  if( test_init( buf ) ) goto fail;

  puts( "ok" );
  return 0;
fail:
  puts("error");
  return -1;
}
