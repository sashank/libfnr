/*
*    libFNR - A reference implementation library for FNR encryption mode.
*
*    FNR represents "Flexible Naor and Reingold" mode

*    FNR is a small domain block cipher to encrypt small domain
*    objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.

*    FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
*
*    fnr.c is written by Scott Fluhrer
*
*    Copyright (C) 2014 , Cisco Systems Inc.
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fnr.h"
#include "openssl/conf.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/err.h"

#define N_ROUND  7 /* Number of Luby-Rackoff rounds we use */
                   /* Needs to be odd */
#define BLOCKSIZE 16 /* AES has 16 bytes blocks.  This is here more for */
                   /* documentation, and not so much in case we change AES */
typedef unsigned char element_t; /* Internally, the PWIP treat vectors as */
#define BITS_PER_ELEMENT 8 /* groups of 8 bit elements.  A more optimized */
                   /* version could use larger elements */
#define ELEMENTS_PER_ROW(N) (((unsigned)N + BITS_PER_ELEMENT - 1) / BITS_PER_ELEMENT)

#define TWEAK_MARKER 0xff /* AES encryptions for the purpose of summarizing */
                   /* a tweak will have 0xff in the last byte */
#define RND_MARKER 0xc0 /* AES encryptions for the purpose of selecting a */
                   /* PWIP will have 0xc0 in the last byte */
/* AES encryptions done during encryption/decryption will have one of the */
/* top two bits of the last byte be clear */
/* This means that the three ways we invoke AES never collide, and so */
/* they can safely share the same key */

/*
 * This is the structure we use to store an expand key.  We also store the
 * arrays used to store the PWIP/invPWIP operations immediately after this
 * structure (in the same malloc block)
 */
struct fnr_expanded_key {
    unsigned full_bytes;  /* Number of bytes that makes up the block, not */
        /* counting the last (even if the last is a full byte) */
    unsigned char final_mask;  /* Which bits of the last byte are part of the */
        /* block */
    unsigned full_elements; /* Number of elements that makes up the block, not */
        /* counting the last (even if the last is full) */
    element_t final_element_mask;  /* Which bits of the last element are part of the */
        /* block */

    unsigned num_bits;    /* Number of bits within the block */
    size_t size;          /* Total size allocated for this structure */
    AES_KEY expanded_aes_key; /* The expanded AES key */
   // unsigned char *aes_key = "01234567890123456"; /* user provided key */
    unsigned char *aes_key ; /* user provided key */
    element_t *green;     /* Pointer to the inverse PWIP structure.  It's */
                          /* actually allocated after this structure */
    element_t red[1];     /* The array used for the forward PWIP structure */
};

/*
 * The encrypt method of AES
 *
 */
int encrypt(unsigned char *plaintext,unsigned int plaintext_len, 
  unsigned char *ciphertext , const unsigned char *key)
{
  EVP_CIPHER_CTX *ctx;

  int len ;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation.  */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
/*
 * When we select a PWIP matrix, we use a stream of bits to do our selection.
 * This is the structure we use to generate those bits.
 * This stream of bits needs to be unpredictable and uniformly distributed
 * if you don't know the key, and determanistic based on the key and the block
 * size.
 *
 * We stir in the block size in case someone uses the same key for two
 * different block sizes; that ensures that the PWIPs generated will be
 * unrelated.
 *
 * This stream is just AES in counter mode.
 */
struct pwip_stream {
    fnr_expanded_key *key;
    unsigned num_bits;   /* The cipher block size */
    unsigned count;      /* Which block we are currently at */
    unsigned index;      /* Which byte in buffer are current at */
    unsigned bit_count;  /* Which bit in buffer we are currently at */
    unsigned char buffer[BLOCKSIZE];
};

static void pwip(const fnr_expanded_key *key, const element_t *m, const void *in, void *out);

/*
 * This returns the next bit from the stream generator
 */
static int next_bit(struct pwip_stream *ctx) {
    if (ctx->index == BLOCKSIZE) {
        /* We ran out of bits from the previous block; generate a new one */
        unsigned char block[BLOCKSIZE] = { 0 };
        unsigned count = ctx->count++;
        block[0] = (count      ) & 0xff;  /* block[0-3] will be the index */
        block[1] = (count >>  8) & 0xff;
        block[2] = (count >> 16) & 0xff;
        block[3] = (count >> 24) & 0xff;
        block[BLOCKSIZE-2] = ctx->num_bits; /* Stir in the block size (so */
            /* that the same key will generate different PWIPs for different */
            /* block sizes) */
        block[BLOCKSIZE-1] = RND_MARKER; /* We set the last byte to this */
            /* value so that we can know that this AES function evaluation */
            /* will be distinct from either the AES evaluations we do during */
            /* tweak expansion, or during the LR rounds */

        //AES_encrypt(block, ctx->buffer, &ctx->key->expanded_aes_key);
        encrypt(block,strlen((char*) block),ctx->buffer, ctx->key->aes_key);

        ctx->index = 0; ctx->bit_count = 0;
    }

    /* Get the next bit from the stream */
    int bit = (ctx->buffer[ ctx->index ] >> ctx->bit_count) & 0x01;

    /* Step to the next bit */
    ctx->bit_count++;
    if (ctx->bit_count == 8) {
        ctx->index++;
        ctx->bit_count = 0;
    }

    /* Return the bit the we retrieved */
    return bit;
}

/* Generate 'n' bits; return them as an int */
static unsigned next_bits(struct pwip_stream *ctx, int n) {
    unsigned result = 0;
    int i;
    for (i=0; i<n; i++) {
        result += next_bit(ctx) << i;
    }

    return result;
}

/*
 * Generate 'n' bits, with the restriction that they are not all zero.
 * This returns them in an array, and returns the index of the first nonzero
 * bit
 * This uses the obvious rejection method: we select all 'n' bits; if they
 * are all zero, then we try again
 */
static int next_bits_not_all_zero(struct pwip_stream *ctx, unsigned char *bits, int n_bits) {
    if (n_bits == 1) {
        bits[0] = 1;
        return 0;
    }

    int first_nonzero = -1;
    do {
        int i;
        for (i=0; i<n_bits; i++) {
            bits[i] = next_bit(ctx);
            if (first_nonzero < 0 && bits[i] != 0) {
                first_nonzero = i;
            }
        }
    } while (first_nonzero < 0);

    return first_nonzero;
}

/*
 * This structure represents an NxN matrix of a specific form:
 * If type == SWAP, then the matrix has the form:
 *    M[x][x] == 1 (if x != a, b)
 *    M[a][b] == 1
 *    M[b][a] == 1
 *    All other elements 0
 *    When you right multiply by this matrix, you end up swapping columns
 *    a and b
 * If type == XOR, then the matrix has the form:
 *    M[x][x] == 1
 *    M[a][b] == 1
 *    All other elements 0
 *    When you right multiply by this matrix, you end up xoring column a
 *    into column b
 * The name refers to that the set of these matricies are "generators" (in the
 * group theory sense) for the group of invertible nxn matricies over GF(2);
 * we can get any invertible matrix by multiplying a collection of these
 * gen_matrices together
 */
struct gen_matrix {
    unsigned char type;
#define SWAP 0
#define XOR 1
    unsigned char a;
    unsigned char b;
};

/*
 * This takes the NxN matrix at A, and right multiplies it by the matrix
 * represented by sub
 */
static void multiply_gen_matrix( int N, element_t *A, struct gen_matrix *sub) {
    int elements_per_row = ELEMENTS_PER_ROW(N);
    int a_row = elements_per_row * (sub->a + 1);
    int b_row = elements_per_row * (sub->b + 1);
    int i;

    switch (sub->type) {
    case SWAP:
        for (i=0; i<elements_per_row; i++, a_row++, b_row++) {
            element_t t = A[ a_row ]; A[ a_row ] = A[ b_row ]; A[ b_row ] = t;
        }
        break;
    case XOR:
        for (i=0; i<elements_per_row; i++, a_row++, b_row++) {
            A[ b_row ] ^= A[ a_row ];
        }
        break;
    }
}

/*
 * This does the hard work of selecting an arbitary affine function is the PWIP
 * (A), and the inverse of that function as the inverse (B)
 */
static int expand_red_green(struct pwip_stream *stream, element_t *A, element_t *B,
                            unsigned n) {
    /*
     * First of all, we select an invertible matrix.  We do this by simulating
     * a Guassian elimination of that matrix; however instead of examining the
     * bits of the matrix (which we can't do; we don't have it yet), we select
     * the steps based on the stream output; we can do this because every bit
     * we examine is independent of every other bit we've previously examined,
     * except for the bits that cannot be all 0 for invertibility.  We encode
     * each step as an 'gen_matrix', which stands for a full nxn matrx (however
     * it's encoded considerably more compactly)
     *
     * The important criteria that we must fulfill is that we select the
     * invertible matrix with a uniform distribution (assuming that the stream
     * generates a uniform independantly distributed stream). This does that,
     * because each matrix corresponds to a unique set of choices, and the
     * number of choices we make is a function of the matrix size (and nothing
     * else).  Because each path of choices are equiprobable, and lead to a
     * unique matrix (and all invertable matrices are possible), then all
     * invertable matrices are equiprobable
     */
    size_t array_byte_size = n * (n - 1) * sizeof (struct gen_matrix) + 1;
    struct gen_matrix *array = malloc( array_byte_size );
    if (!array) return 0;
    int index = 0;
#define SET(x, y, z)  (void)( array[index].type = x, array[index].a = y, array[index].b = z, index++ )

    unsigned i;
    unsigned char bits[128];
    for (i=0; i<n; i++) {
        int j;

        /*
         * First step in our simulated Gaussian: examine the bits in column i,
         * from rows i through n; swap row i with first row with a 1 bit in the
         * column
         * Now, if all those bits in the column are 0, the matrix is
         * noninvertible; we're looking only for invertable matrices, and so
         * ask the stream to avoid an all-0 result
         */
        int first_nonzero = next_bits_not_all_zero(stream, bits, n-i);
        /*
         * first_nonzero is the row (out of the ones we picked) that's the first
         * one
         * If the top row wasn't it, we need to swap the rows
         */
        if (first_nonzero > 0) {
            SET(SWAP, i, i+first_nonzero);
            bits[first_nonzero] = 0;
        }

        /*
         * Here in Guassian elimination, we would typically multiply row i with
         * the inverse of the value in column i, in order to make the value on
         * the diagonal 1.  However, we're in GF(2); it's already 1, and so we
         * can skip that step
         */

        /*
         * Go through the later rows; for any row that had a 1 bit, cancel it
         * out (by adding row i that to that row)
         */
        for (j=1; j<n-i; j++) {
            if (bits[j]) {
                SET(XOR, i, i+j);
            }
        }

        /*
         * Now that row i has a 1, we simulate the values in that column of the
         * previous rows; for those rows that had a 1 there, cancel it out
         */
        for (j=0; j<i; j++) {
            if (next_bit(stream)) {
                SET(XOR, i, j);
            }
        }

        /*
         * So, we've set column i to be all 0's except for row i, which has a
         * 1, and we've done it without disturbing the pattern in the previous
         * columns
         */
    }
    memset( bits, 0, sizeof bits );

    /*
     * At this point, the simulated matrix is now the identity, and (here's the
     * point we're actually interested in), the gen_matrices in array tells us
     * exact how we got there; hence multiplying those matricies will give us
     * back the original simulated matrix
     */ 

    /*
     * Ok, it's time to reconstruct that matrix; set A and B both to be the
     * identity matrix
     */
    int elements_per_row = ELEMENTS_PER_ROW(n);

    memset( &A[elements_per_row], 0, n * elements_per_row );
    memset( &B[elements_per_row], 0, n * elements_per_row );
    unsigned char bit = 0;
    int column = -1;
    for (i=0; i<n; i++) {
        if (i % 8 == 0) {
            bit = 1;
            column++;
        }
        A[elements_per_row + i*elements_per_row + column] =
        B[elements_per_row + i*elements_per_row + column] = bit;
        bit <<= 1;
    }

    /*
     * Multiply the gen_matricies in the reverse order they were generatd; this
     * will reconstruct the original invertible matrix (which was simulated;
     * we're rederive what the original simulated value was)
     */
    for (i=index; i>0; i--) {
        multiply_gen_matrix( n, A, &array[i-1] );
    }

    /*
     * Now we need to compute the inverse to that matrix.  We could do Yet
     * Another Gaussian elimination to invert it; however there's a simpler
     * approach.  We note that:
     * - All the gen_matrices are self-inverses; that is, they all have
     *   A * A = I, or in other words, A = A^-1
     * - Matrix multiplication has this identity (A * B)^-1 = B^-1 * A^-1
     * Hence, if A, B, ... Z are all gen_matrices, we have:
     *   (A * B * ... * Z)^1 = Z^-1 * ... * B^-1 * A^-1 = Z * ... * B * A
     * Or, by multiplying them in the other direction, we get the inverse
     * Ain't that cool!
     */
    for (i=0; i<index; i++) {
        multiply_gen_matrix( n, B, &array[i] );
    }

    memset( array, 0, array_byte_size );
    free(array);

    /*
     * Ok, we've selected the invertible matrix; now it's time to select the
     * constant vector.  In the forward direction, pick it based on the stream
     */
    column = -1;
    int shift = 0;
    for (i=0; i<n; i+=8) {
        int bits_this_time = n-i; if (bits_this_time > 8) bits_this_time = 8;
        A[i/8] = next_bits(stream, bits_this_time);
    }

    /*
     * Now it is time to add the corresponding vector to the inverse transform.
     * One straightforward approach would be to modify the inverse transform so
     * that we add the constant to the value we're transforming (rather than
     * the output); so in the forward direction we compute PWIP(V) = M*V + C,
     * and in the reverse direction, we compute InvPWIP(V) = InvM*(V + C)
     * (why InvM*(V+C) and not InvM*(V-C)? Remember, we're working on vectors
     * over GF(2), and so + and - are the same operation).
     * That would work fine; however I'd prefer to reuse the same code in both
     * directions, and so we compute InvC = InvM * C, and hence in the reverse
     * direction, we compute InvPWIP(V) = InvM*V + InvC
     */
    /* Set the constant vector assigned to the B operation to 0 */
    memset( &B[0], 0, elements_per_row * sizeof(element_t) );

    /*
     * Now, take the constant vector assigned to A (which is at the beginning
     * of the A array; hence A is a pointer to it), and send it through the B
     * operation (which computes InvM * A + 0; the 0 is because we just set the
     * constant vector assigned to B to 0), and place that result back where
     * the constant vector assigned to B, which is at the beginning of B
     */
    pwip(stream->key, B, A, B);

    /*
     * Here, A and B represent uniformly distributed affine functions
     * (if next_bit() generates independent and uniformly distributed bits)
     * which are inverses of each other
     */

    return 1;
}

/*
 * This takes an AES key (and a block size), and expands it, setting all the 
 * internal parameters (and the PWIP matrices, which is most of the work)
 */
fnr_expanded_key *FNR_expand_key(const void *aes_key, unsigned aes_key_size,
                                 unsigned num_bits) {
    if (num_bits < 1 || num_bits > 128) {
        /* Parameter out of range */
        return 0;
    }

    /*
     * Compute how much size the expanded key will take up; that's the
     * fixed structure, as well as the variable sized arrays that hold the PWIP
     * matrices
     */
    int elements_per_row = ELEMENTS_PER_ROW(num_bits);
    size_t size = sizeof(fnr_expanded_key) + 2 * elements_per_row * (num_bits + 1);
    fnr_expanded_key *key = malloc( size );
    if (!key) {
        return 0;
    }

    /* Store the various blocksize-dependent constants */
   
    /* The number of bytes (not counting the last byte) */ 
    key->full_bytes = (num_bits-1)/8;
    /* The number of elements (not counting the last one */ 
    key->full_elements = key->full_bytes;  /* element_t == unsigned char */
    /* The bits that are used in the last byte */
    key->final_mask = 0xff & ((1<<((num_bits+7)%8 + 1)) - 1);
    /* The number of elements (not counting the last one */ 
    key->final_element_mask = key->final_mask;  /* element_t == unsigned char */
    /* The size of the block (in bits) */
    key->num_bits = num_bits;
    /* The size of the structure */
    key->size = size;
    /* Where the inverse PWIP matrix is stored (the forward PWIP is */
    /* immediately after the fixed structure) */
    key->green = key->red + elements_per_row * (num_bits + 1);

    /* Expand the AES key */
    if (AES_set_encrypt_key(aes_key, aes_key_size, &key->expanded_aes_key) != 0) {
        free(key);
        return 0;
    }
   
    key->aes_key = calloc(1, aes_key_size + 1);
    memcpy(key->aes_key, aes_key, aes_key_size);

    /* Now the hard part; select an affine function, and its inverse */
    struct pwip_stream stream;
    stream.key = key;
    stream.num_bits = num_bits;
    stream.count = 0;
    stream.index = BLOCKSIZE;

    if (!expand_red_green( &stream, key->red, key->green, num_bits )) {
        free(key);
        return 0;
    }

    /* Ok, all done; erase any incriminating evidence and get out */
    memset( &stream, 0, sizeof stream );

    return key;
}

/*
 * Safely get rid of an expanded key
 */
void FNR_zeroize_key (fnr_expanded_key *key)
{
    if (!key) return;
    memset( key, 0, key->size );
    free(key);
}

/*
 * This takes an arbitrary byte string, and "expands" it into a form that can
 * be used by the encrypt/decrypt routines
 * Actually, in this case, "expand" is not quite the correct terminology;
 * instead, it summarizes the arbitrary length string into a fixed length form;
 * and in such a way that any modification to the tweak will completely alter
 * the summary
 * A cryptographic hash would be perfect; we don't assume we have one of those
 * available. So, what we do is a variant on a CBC-MAC (with the length of the
 * string in front, so we don't have to worry about length extension attacks
 * (which wouldn't apply anyways, but still...))
 */
void FNR_expand_tweak(fnr_expanded_tweak *expanded_tweak,
                    const fnr_expanded_key *key,
                    const void *tweak, size_t len_tweak) {
    unsigned char block[BLOCKSIZE] = { 0 };

    block[0] = len_tweak & 0xff;
    block[1] = len_tweak >> 8;  /* Tweaks > 255 bytes are unlikely, and */
    block[2] = len_tweak >> 16; /* >64k is downright silly,  but still */
    block[3] = len_tweak >> 24; /* we might as well acknowledge the */
                                /* possibility */
    block[4] = key->num_bits;  /* This is so if we use the same key for two */
                     /* different block sizes, the transforms are unrelated */
    unsigned n = 5;  /* We've just placed 5 bytes into block */
    const unsigned char *input = tweak;

    do {
        for (; n<BLOCKSIZE-1 && len_tweak; n++) {
            block[n] ^= *input++;
            len_tweak--;
        }
        block[BLOCKSIZE-1] = TWEAK_MARKER;  /* We set the last byte to this */
            /* value so that we can know that this AES function evaluation */
            /* will be distinct from either the AES evaluations we do during */
            /* PWIP selection, or during the LR rounds */

        n = 0;

        //AES_encrypt(block, block, &key->expanded_aes_key);
        encrypt(block,strlen((char*) block),block, key->aes_key);
    } while (len_tweak > 0);

    memcpy( expanded_tweak, block, BLOCKSIZE-1 );
    memset( block, 0, sizeof block );
}

/*
 * This computes a pairwise independent permutation of in, and places the
 * result into out
 * A pairwise independent permutation is a permutation that has the property
 * that, assuming a random (uniformly distributed key), that any two distinct
 * inputs A, B, and any two distinct outputs X, Y, the probability that
 * X=PWIP(A) and Y=PWIP(B) is uniform, that is, is 1/(2**n * (2**n-1))
 * independent of A, B, X, Y 
 *
 * This function actually achieves the stronger Threeway Independent
 * Permutation criteria, for three distinct inputs A, B, C, and three distinct
 * outputs X, Y, Z, the probability that X=PWIP(A), Y=PWIP(B), Z=PWIP(C) is
 * independent of A, B, C, X, Y, Z
 *
 * This works by using binary matrix multiplication, the input vector is
 * treated as a vector in GF(2); it is multiplied by a randomly (uniformly
 * distributed) nxn matrix of GF(2) elements, and then added with a random
 * vector in GF(2), resulting in a random (uniformly distributed) affine
 * function
 *
 * The structure of the m vector:
 * - The first elements_per_row elements is the constant vector (which we end
 *   up adding at the start, not as a final step)
 * - Then, each successive elements_per_row set of elements this the next
 *   row of the matrix; there are N of these rows
 */
static void pwip(const fnr_expanded_key *key, const element_t *m,
                 const void *in, void *out) {
    unsigned i, j;
    const unsigned char *input = in;
    element_t *result = out;

    /*
     * Initialize the output with the constant vector
     */
    unsigned elements_per_row = key->full_elements;
    for (i=0; i<elements_per_row; i++) {
        result[i] = *m++;
    }
    /*
     * Copy over the last (possibly partial byte), being careful not to
     * overwrite any bits that's not in the output vector
     */
    unsigned final_mask = key->final_element_mask;
    result[i] = (result[i] & ~final_mask) | *m++;

    /*
     * Now step through the input bits one at a time; if each bit is one, xor
     * in the corresponding row from the matrix
     */
    unsigned char a = 0;
    unsigned num_bits = key->num_bits;
    for (i=0; i<num_bits; i++) {
        if (i % BITS_PER_ELEMENT == 0) a = *input++;
        element_t mask = -(a&1);  /* Assumes two's complement */
        a >>= 1;
        /*
         * Here, mask == 0 if the bit is 0, mask == 0xff if the bit is one
         * An 'if' statement would be clearer; however this implementation has
         * the advantage that it runs in constant time and with constant
         * memory references
         */
        for (j=0; j<=elements_per_row; j++) {
            result[j] ^= mask & *m++;
        }
    }
}

/*
 * This is the actual cipher implementation.  The encrypt and the decrypt
 * operations are identical, except for the order of the subkeys
 */
static void FNR_operate(const fnr_expanded_key *key, fnr_expanded_tweak *tweak,
                        const void *in, void *out, int round, int round_inc ) {
    unsigned char text[BLOCKSIZE] = { 0 };

    /*
     * First step: run a key-dependent Pair Wise Independent Permutation on the
     * input block (and, at the same time, copy it to somewhere which we can
     * modify)
     */ 
    pwip( key, key->red, in, text );

    /*
     * Now, we run 7 rounds of Luby-Rackoff (aka a Feistel network).  This is
     * slightly different from most implementations of LR, in that we don't
     * divide the block into two separate halves; instead, we use the even
     * bits as one half and the odd bits as other half, and we don't swap
     * them; instead, we alternate between rounds which half we use as the
     * input to our random function, and which half we xor the output of the
     * random function into.  Since we have an odd number of rounds, this
     * all works out.
     * Nits: if the block we're encrypting has an odd number of bits, this is
     * strictly speaking an unbalanced Feistel (if unbalanced only by a single
     * bit).  In addition, if we're encrypting a single bit, this really isn't
     * a Feistel at all (because one half is empty).
     */
    int i;
    unsigned char block[BLOCKSIZE];  /* This is the temp block we use to */
                                     /* compute the LR round function */
    unsigned mask = 0x55;    /* This determines whether the even bits or */
                             /* the odd bits are the 'active' half */
    unsigned full_bytes = key->full_bytes; /* This is the number of bytes */
                             /* make up the block, not counting the last */
                             /* (possibly partial) byte */
    unsigned input_len = (full_bytes + 1); /* This is the number of chars in input */
    unsigned final_mask = key->final_mask; /* This indicates which bits of */
                             /* the (possibly partial) last byte actually */
                             /* participate */

    for (i=0; i<N_ROUND; i++, round += round_inc) {
        /*
         * In a LR network, in each round, we take a complex key-dependent
         * function of one half, and xor it into the other half (and then on
         * the next round, the same, but in the other direction)
         * This is how we do it:
         */

        /*
         * Step 1: fill the temp block with the tweak-dependent data (and the
         * round index so that this block is different for every round)
         */
        memcpy( block, tweak, BLOCKSIZE-1 );
        block[BLOCKSIZE-1] = round; /* Slide attacks; just say no */

        /*
         * Step 2: xor in the bits from the 'active bits' from the block
         */
        unsigned j;
        for (j=0; j<full_bytes; j++) {
            block[j] ^= text[j] & mask;
        }
        /* xor in the bits from the last byte (which may be partial) */
        block[j] ^= text[j] & mask & final_mask;

        /*
         * Step 3: send the temp block through the AES function, generating a
         * ciphertext block that is a complex function of the tweak, the round
         * number and the stirred in data bits
         */
        //AES_encrypt(block, block, &key->expanded_aes_key);
        encrypt(block,input_len,block, key->aes_key);

        /*
         * Step 4: swap the 'active bits' (so that if the even bits were
         * active, now the odd bits will be)
         */
        mask ^= 0xff;

        /*
         * Step 5: xor the bits from the temp block into the 'active bits' from
         * the block, and leave the bits that are not 'active' alone.  Since we
         * just swapped the active bits, the active bits will be precisely
         * those bits we didn't send through the AES function
         * Note that this may also overwrite a few unused bits in the last
         * partial byte; since we'll never depend on those, that doesn't cause
         * a problem
         */
        for (j=0; j<=full_bytes; j++) {
            text[j] ^= block[j] & mask;
        }

    }

    /*
     * Last step: run the inverse key-dependent Pair Wise Independent
     * Permutation on the output block (and, at the same time, copy it to where
     * we were asked)
     */ 
    pwip( key, key->green, text, out );

    /* Zeroize temp data; it's good crypto hygiene */
    memset( block, 0, sizeof block );
    memset( text, 0, sizeof text );
}

void FNR_init(){
   /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

void FNR_shut(){
    /* Clean up */
  EVP_cleanup();
  ERR_free_strings();
}

void FNR_encrypt( fnr_expanded_key *key, fnr_expanded_tweak *tweak, const void *plaintext, void *ciphertext) {
    /* Run the cipher, going through rounds 1,2,3,4,5,6,7 */
    FNR_operate( key, tweak, plaintext, ciphertext, 1, 1 );
}

void FNR_decrypt( fnr_expanded_key *key, fnr_expanded_tweak *tweak, const void *ciphertext, void *plaintext) {
    /* Run the cipher, going through rounds 7,6,5,4,3,2,1 */
    FNR_operate( key, tweak, ciphertext, plaintext, N_ROUND, -1 );
}

