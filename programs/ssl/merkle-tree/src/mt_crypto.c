/* Copyright (c) IAIK, Graz University of Technology, 2015.
 * All rights reserved.
 * Contact: http://opensource.iaik.tugraz.at
 *
 * This file is part of the Merkle Tree Library.
 *
 * Commercial License Usage
 * Licensees holding valid commercial licenses may use this file in
 * accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and SIC. For further information
 * contact us at http://opensource.iaik.tugraz.at.
 *
 * Alternatively, this file may be used under the terms of the GNU General
 * Public License as published by the Free Software Foundation version 2.
 *
 * The Merkle Tree Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with the Merkle Tree Library. If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 * \brief Implements the Merkle Tree hash interface using SHA-256 the hash
 * function.
 */

#include "mbedtls/sha256.h"

#include "mt_crypto.h"

//----------------------------------------------------------------------
mt_error_t mt_hash(const mt_hash_t left, const mt_hash_t right,
    mt_hash_t message_digest) {
    int ret;
    mbedtls_sha256_context ctx;

    if (!(left && right && message_digest)) {
        return MT_ERR_ILLEGAL_PARAM;
    }

    mbedtls_sha256_init( &ctx );


    if( ( ret = mbedtls_sha256_starts_ret( &ctx, 0 ) ) != 0 )
    {
        ret = MT_ERR_ILLEGAL_STATE;
        goto exit;
    }

    if( ( ret = mbedtls_sha256_update_ret( &ctx, right, HASH_LENGTH ) ) != 0 )
    {
        ret = MT_ERR_ILLEGAL_STATE;
        goto exit;
    }

    if( ( ret = mbedtls_sha256_update_ret( &ctx, left, HASH_LENGTH ) ) != 0 )
    {
        ret = MT_ERR_ILLEGAL_STATE;
        goto exit;
    }

    if( ( ret = mbedtls_sha256_finish_ret( &ctx, message_digest ) ) != 0 )
    {
        ret = MT_ERR_ILLEGAL_STATE;
        goto exit;
    }

exit:
    mbedtls_sha256_free( &ctx );

    return( ret );
}

