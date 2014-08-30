/*
*    libFNR - A reference implementation library for FNR encryption .
*
*    FNR represents "Flexible Naor and Reingold" 

*    FNR is a small domain block cipher to encrypt small domain
*    objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.

*    FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
*
*    fnr.h is written by Scott Fluhrer 
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
#ifndef HEADER_FNR_H_
#define HEADER_FNR_H_

/*
 * This is a utility to do small block encryption, with a variable sized block
 * between 1 and 128 bits, and with no ciphertext expansion (that is, the
 * ciphertext is precisely the same length as the plaintext)
 *
 * It isn't very efficient (it's not; after all, every encryption or decryption
 * operation involves 7 calls to AES); it is designed to be secure.
 *
 * Here are the concepts behind it:
 * - key -- This is the secret used to specify how to transform.  This is the
 *        part that you share between the encryptor and decryptor, and what
 *        needs to be kept secret from anyone listening in.  We use the same
 *        key sizes as AES (128, 192, 256 bits; expressed as a byte string).
 *
 * - tweak -- This is a parameter that modifies how the encryption is done.
 *        This is designed so that the same key can be used to protect
 *        different fields, in such a way so that if someone learns that
 *        plaintext xxx corresponds to ciphertext yyy in context A, they still
 *        have no information what yyy means in context B.  The idea is that
 *        you'd use a string the identifies the context as the tweak. As such,
 *        the tweak has the following properties: 1) the encryption process
 *        with the same key and two different tweaks are unrelated; 2) there is
 *        no security problem with making the tweak public (unlike the key),
 *        3) the tweak is cheap to update (a lot cheaper than the key, in this
 *        case)
 *
 *        We support arbitrary bytestrings as tweaks
 *
 * - plaintext/ciphertext -- These are n-bit binary fields, with n being
 *        between 1 and 128 (and you specify it while expanding the key).
 *        These are represented by strings of unsigned char's, with each
 *        unsigned char holding 8 bits.  If n is not a multiple of 8, then we
 *        handle the last partial byte by using the lsbits in the last byte;
 *        the msbits of that unsigned char are assumed not to be a part of the
 *        plaintext/ciphertext
 *
 * Now, encryption/decryption is determanistic; if we encrypt the same
 * plaintext twice with the same key and tweak, you will always get the same
 * ciphertext.  This is a side effect of not having any ciphertext expansion,
 * there are 2**N possible plaintexts and 2**N possible ciphertexts, and so
 * (for a fixed key/tweak) there has to be a 1:1 mapping.          
 *
 * Here's how you use it:
 *
 * Step 1: convert your key (128, 192 or 256 bit -- this is based on AES, and
 * this key will be directly fed to it) into expanded form:
 *
 *     fnr_expanded_key *key = FNR_expand_key( aes_key, aes_key_size,
 *                                             block_size );
 *     if (!key) error_handling();
 *
 * The block_size parameter is the of blocks we'll encrypt with this key; it
 * must be a value between 1 and 128 bits.  Why anyone would want to encrypt
 * a 1 bit block, I have no idea, but still...
 *
 * You can reuse this key everytime you need to encrypt or decrypt with this
 * key and this block size.  If you want to use the same key with a different
 * block size, that's fine (that won't cause a security problem), but you'll
 * need to reexpand the key
 *
 * Step 2: expand your tweak (which is public data that modifies how the
 * encryption is done; one way of thinking of this is to look at it as another
 * part of the key, but one which can be made public, and which is cheap to
 * change):
 *
 *     fnr_expanded_tweak tweak;
 *     FNR_expand_tweak(&tweak, key, arbitrary_bytestring, length_of_bytestring);
 *
 * The tweak may consist of an arbitrary bytestring.
 * 
 * If you use the same tweak for multiple encryptions/decryptions, you can use
 * the same expanded tweak.
 *
 * If you don't have a tweak, you need to expand a 0-length tweak.  Perhaps we
 * could have the encrypt/decrypt routines interpet a NULL tweak as the
 * 0-length; we currently don't bother (as 0-length tweaks may not occur often
 * enough)
 *
 * Step 3: encrypt and decrypt your data
 *
 *     FNR_encrypt(key, &tweak, plaintext, ciphertext);
 *     FNR_decrypt(key, &tweak, ciphertext, plaintext);
 *
 * Encrypting/decrypting in place (plaintext==ciphertext) is allowed; because
 * the plaintext and the ciphertext are the same size, you may want to do this
 *
 * Here, plaintext and ciphertext are the number of bits long you specified
 * when you expanded the key.  Now, if you specified a length that's not a
 * multiple of 8, here's how we handle that case: if you specify such an odd
 * size N, we take all the N/8 bytes, plus the remaining N%8 lsbits from the
 * next byte. When we write, we are careful not to disturb any bits outside the
 * N bit region. For example, if we have a 4 bit ciphertext, we'll update the
 * lower 4 bits of *ciphertext, and leave the remaining upper 4 bits
 * undisturbed.
 *
 * Step last: when you're done with the key, you discard it with:
 *
 *     FNR_release_key(key);
 *
 * (there's no need to release the expanded tweak)
 */

/* The structure of an expanded key; its contents are private */
typedef struct fnr_expanded_key_st fnr_expanded_key;

/*
 * This is the 'expanded tweak'; that is, the tweak summarized in a form that
 * we can give to the encryption/decryption routine
 */
typedef struct fnr_expanded_tweak_st{
    unsigned char tweak[15];
} fnr_expanded_tweak;

/*
 * This takes an aes key (aes_key ad aes_key_size), and expands it into an
 * expanded form for use
 * Parameters:
 * aes_key - This is the 128 bit (16 byte), 192 bit (24 byte) or 256 bit (32
 *           byte) key.
 * aes_key_size - This is the length of the above key, in bits.  That is, it
 *           is either 128, 192 or 256
 * num_text_bits - This is the size of the plaintext/ciphertexts that we will
 *           encrypt, in *bits*.  That is, it is between 1 and 128 (using a
 *           1 bit plaintext/ciphertexts isn't greatly encouraged, but it is
 *           allowed)
 * This returns the expanded key on success, NULL on failure
 */
fnr_expanded_key *FNR_expand_key(const void *aes_key, unsigned int aes_key_size,
                                size_t num_text_bits);

/*
 * This frees an expanded key.  It should be called when you're done with the key
 * (as the key expansion malloc's memory)
 * Parameters:
 * key - The expanded key to deallocate (and release)
 */
void FNR_release_key(fnr_expanded_key *key);

/*
 * This takes a tweak, and expands it
 * A zero-length tweak is perfectly legal
 * Parameters:
 * expanded_tweak - This is where to place the expanded tweak.
 * key            - This is the expanded key that the tweak will be used with.
 * tweak          - This is tweak to expand.
 * len_tweak      - This is the length of the tweak, in bytes.
 */
void FNR_expand_tweak(fnr_expanded_tweak *expanded_tweak,
                      const fnr_expanded_key *key,
                      const void *tweak, size_t len_tweak );
/*
 * This method initializes and loads the needed algos
 * and sets the stage
 */
void FNR_init(void);

/*
 * This method  frees up and cleans 
 */

void FNR_shut(void);
/*
 * This encrypts a message using the expanded key and tweak
 * Parameters:
 * key        - The expanded key
 * tweak      - The expanded tweak
 * plaintext  - The value to be encrypted
 * ciphertext - Where to place the result of the encryption
 *
 * Encrypting in place (plaintext==ciphertext) is allowed
 */
void FNR_encrypt(const fnr_expanded_key *key,const fnr_expanded_tweak *tweak,
                 const void *plaintext, void *ciphertext);
/*
 * This decrypts a message using the expanded key and tweak
 * Parameters:
 * key        - The expanded key
 * tweak      - The expanded tweak
 * ciphertext - The value to be decrypted
 * plaintext  - Where to place the result of the decryption
 *
 * Decrypting in place (ciphertext==plaintext) is allowed
 */
void FNR_decrypt(const fnr_expanded_key *key, const fnr_expanded_tweak *tweak,
                 const void *ciphertext, void *plaintext);

void FNR_handle_errors(void);

void FNR_burn( void *v, size_t n );
#endif /* HEADER_FNR_H_ */
