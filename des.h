/**
 * \file des.h
 *
 * \brief DES block cipher
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef DES_H
#define DES_H


#include <stddef.h>
#include <stdint.h>

#define DES_ENCRYPT     1
#define DES_DECRYPT     0

#define ERR_DES_INVALID_INPUT_LENGTH              -0x0032  /**< The data input has an invalid length. */

#define DES_KEY_SIZE    8

#define DES3_KEY2_SIZE       (16)
#define DES3_KEY3_SIZE       (24)



#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          DES context structure
 */
typedef struct
{
    uint32_t sk[32];            /*!<  DES subkeys       */
}
des_context;

/**
 * \brief          Triple-DES context structure
 */
typedef struct
{
    uint32_t sk[96];            /*!<  3DES subkeys      */
}
des3_context;

/**
 * \brief          Initialize DES context
 *
 * \param ctx      DES context to be initialized
 */
void des_init( des_context *ctx );

/**
 * \brief          Clear DES context
 *
 * \param ctx      DES context to be cleared
 */
void des_free( des_context *ctx );

/**
 * \brief          Initialize Triple-DES context
 *
 * \param ctx      DES3 context to be initialized
 */
void des3_init( des3_context *ctx );

/**
 * \brief          Clear Triple-DES context
 *
 * \param ctx      DES3 context to be cleared
 */
void des3_free( des3_context *ctx );

/**
 * \brief          Set key parity on the given key to odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 */
void des_key_set_parity( unsigned char key[DES_KEY_SIZE] );

/**
 * \brief          Check that key parity on the given key is odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \return         0 is parity was ok, 1 if parity was not correct.
 */
int des_key_check_key_parity( const unsigned char key[DES_KEY_SIZE] );

/**
 * \brief          Check that key is not a weak or semi-weak DES key
 *
 * \param key      8-byte secret key
 *
 * \return         0 if no weak key was found, 1 if a weak key was identified.
 */
int des_key_check_weak( const unsigned char key[DES_KEY_SIZE] );

/**
 * \brief          DES key schedule (56-bit, encryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 */
int des_setkey_enc( des_context *ctx, const unsigned char key[DES_KEY_SIZE] );

/**
 * \brief          DES key schedule (56-bit, decryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 */
int des_setkey_dec( des_context *ctx, const unsigned char key[DES_KEY_SIZE] );

/**
 * \brief          Triple-DES key schedule (112-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 */
int des3_set2key_enc( des3_context *ctx,
                      const unsigned char key[DES_KEY_SIZE * 2] );

/**
 * \brief          Triple-DES key schedule (112-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 */
int des3_set2key_dec( des3_context *ctx,
                      const unsigned char key[DES_KEY_SIZE * 2] );

/**
 * \brief          Triple-DES key schedule (168-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 */
int des3_set3key_enc( des3_context *ctx,
                      const unsigned char key[DES_KEY_SIZE * 3] );

/**
 * \brief          Triple-DES key schedule (168-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 */
int des3_set3key_dec( des3_context *ctx,
                      const unsigned char key[DES_KEY_SIZE * 3] );

/**
 * \brief          DES-ECB block encryption/decryption
 *
 * \param ctx      DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 */
int des_crypt_ecb( des_context *ctx,
                    const unsigned char input[8],
                    unsigned char output[8] );


/**
 * \brief          DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      DES context
 * \param mode     DES_ENCRYPT or DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
int des_crypt_cbc( des_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output );

/**
 * \brief          3DES-ECB block encryption/decryption
 *
 * \param ctx      3DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 */
int des3_crypt_ecb( des3_context *ctx,
                     const unsigned char input[8],
                     unsigned char output[8] );


/**
 * \brief          3DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      3DES context
 * \param mode     DES_ENCRYPT or DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
int des3_crypt_cbc( des3_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output );


/**
 * \brief          Internal function for key expansion.
 *                 (Only exposed to allow overriding it,
 *                 see DES_SETKEY_ALT)
 *
 * \param SK       Round keys
 * \param key      Base key
 */
void des_setkey( uint32_t SK[32],
                         const unsigned char key[DES_KEY_SIZE] );



/**
 * \brief          DES-CBC buffer encryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des_ecb_encrypt(unsigned char *pout,
							 unsigned char *pdata,
							 unsigned int nlen,
							 unsigned char *pkey);
/**
 * \brief          DES-CBC buffer decryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des_ecb_decrypt(unsigned char *pout,
							 unsigned char *pdata
							 ,unsigned int nlen,
							 unsigned char *pkey);
/**
 * \brief          DES-CBC buffer encryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 * \param piv		initialization vector (updated after use)
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des_cbc_encrypt(unsigned char *pout,
							 unsigned char *pdata,
							 unsigned int nlen,
							 unsigned char *pkey,
							 unsigned char *piv);
/**
 * \brief          DES-CBC buffer decryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 * \param piv		initialization vector (updated after use)
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des_cbc_decrypt(unsigned char *pout,
							 unsigned char *pdata,
							 unsigned int nlen,
							 unsigned char *pkey,
							 unsigned char *piv);

/**
 * \brief          3DES-ECB buffer encryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 * \param klen		length of the input key
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des3_ecb_encrypt(unsigned char *pout,
							  unsigned char *pdata,
							  unsigned int nlen,
							  unsigned char *pkey,
							  unsigned int klen);
/**
 * \brief          3DES-ECB buffer decryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 * \param klen		length of the input key
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des3_ecb_decrypt(unsigned char *pout,
							  unsigned char *pdata,
							  unsigned int nlen,
							  unsigned char *pkey,
							  unsigned int klen);
/**
 * \brief          3DES-CBC buffer encryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 * \param klen		length of the input key
 * \param piv		initialization vector (updated after use)
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des3_cbc_encrypt(unsigned char *pout,
							  unsigned char *pdata,
							  unsigned int nlen,
							  unsigned char *pkey,
							  unsigned int klen,
							  unsigned char *piv);
/**
 * \brief          3DES-CBC buffer decryption
 *
 * \param pout		buffer holding the output data
 * \param pdata		buffer holding the input data
 * \param nlen		length of the input data
 * \param pkey		buffer holding the key data
 * \param klen		length of the input key
 * \param piv		initialization vector (updated after use)
 *
 * \return         0 if successful, or ERR_DES_INVALID_INPUT_LENGTH
 */
unsigned int des3_cbc_decrypt(unsigned char *pout,
							  unsigned char *pdata,
							  unsigned int nlen,
							  unsigned char *pkey,
							  unsigned int klen,
							  unsigned char *piv);




#ifdef __cplusplus
}
#endif



/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int des_test_self( void );



#endif /* des.h */
