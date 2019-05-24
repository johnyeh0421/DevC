/*
 *  Public Key layer for parsing key files and structures
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PK_PARSE_C)

#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include <string.h>

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif
#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif
#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif
#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif


#if defined(MBEDTLS_FS_IO)
/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * Load all data from a file into a given buffer.
 *
 * The file is expected to contain either PEM or DER encoded data.
 * A terminating null byte is always appended. It is included in the announced
 * length only if the data looks like it is PEM encoded.
 */


char rootCA_crt[] =		"-----BEGIN CERTIFICATE-----\r\nMIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB\r\nyjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\r\nExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\r\nU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\r\nZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\r\naG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL\r\nMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\r\nZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln\r\nbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp\r\nU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y\r\naXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1\r\nnmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex\r\nt0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz\r\nSdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG\r\nBO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+\r\nrCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/\r\nNIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E\r\nBAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH\r\nBgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\r\naXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv\r\nMzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE\r\np6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y\r\n5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK\r\nWE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ\r\n4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N\r\nhnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\r\n-----END CERTIFICATE-----\r\n";
char cert_pem[] = 		"-----BEGIN CERTIFICATE-----\r\nMIIDWDCCAkCgAwIBAgITYWN7DUtLqMCMS7Rgh8cjXdIfuDANBgkqhkiG9w0BAQsF\r\nADBNMUswSQYDVQQLDEJBbWF6b24gV2ViIFNlcnZpY2VzIE89QW1hem9uLmNvbSBJ\r\nbmMuIEw9U2VhdHRsZSBTVD1XYXNoaW5ndG9uIEM9VVMwHhcNMTYwODA4MDYyNDEy\r\nWhcNNDkxMjMxMjM1OTU5WjAeMRwwGgYDVQQDDBNBV1MgSW9UIENlcnRpZmljYXRl\r\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnuWmrgz5RRxAi8AO45qo\r\ncrVDzCli8hjjihMzP3M2CoaHW4snffs7tSv4fLzwruiQkQFbJEP9h3s77TQYz/G5\r\n92XYBOY7bwCqw9m2aGZfV1cDoXrOupITJudWgPoY7k+V/pPmtL8aMXcUnKPhiOqR\r\n/ljqtc6EkBwqb186hYuQzuCypJjuod7anCPTB69yj5w9vwXic8Y4IUZ0mXCAXY34\r\nMCnRh8DQZXsqNXU7y7TPvTOz++Ml4YYTm2ry/PXN4jIYdiRH2XLyYFbPxqw2D209\r\n+Hd0OqoPMc/LiDFs7PETpvr+aJY2byJDKljhEwv2i45wSTd+BLmaILVw6k3AnWoQ\r\nkwIDAQABo2AwXjAfBgNVHSMEGDAWgBRacDNum9N/YhT0YKWlwPBFpVCPzTAdBgNV\r\nHQ4EFgQUh4Bti77qU1LeZx8IyZ/kb3G1SWswDAYDVR0TAQH/BAIwADAOBgNVHQ8B\r\nAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBABSfTvIift6eNoHoEoWLeJ0YNgBo\r\nRWZ41Sag3LejjA7n+osDRNtDC2pvgexOogKvY+o3Bbg9bobJelHskSXcKn74LfXR\r\n8fnhdU4OkOb+lkdpRI8Kg8o8Xd579m561JEBNMKrVTU9a/zM9285g9UgN9w0skGc\r\nkgP5AwZoeE0XKFS7/E5f+BKEi13l1ZG5j1eavNyWm8b3/9ZLx0yeKhixE3/dym/7\r\ncli4RvAQwoF66oHpMjRksjSyJg8uIkZIcnFhFdD9BibIVqdaMemCDYVwRuZ6D7Vy\r\nwBkfh3pih4sFIm/T6YrSrxsnVquDFyY/QmskLdezVr/mnntOBDVtMsZScQM=\r\n-----END CERTIFICATE-----\r\n\r\n";
char privkey_pem[] = 	"-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEAnuWmrgz5RRxAi8AO45qocrVDzCli8hjjihMzP3M2CoaHW4sn\r\nffs7tSv4fLzwruiQkQFbJEP9h3s77TQYz/G592XYBOY7bwCqw9m2aGZfV1cDoXrO\r\nupITJudWgPoY7k+V/pPmtL8aMXcUnKPhiOqR/ljqtc6EkBwqb186hYuQzuCypJju\r\nod7anCPTB69yj5w9vwXic8Y4IUZ0mXCAXY34MCnRh8DQZXsqNXU7y7TPvTOz++Ml\r\n4YYTm2ry/PXN4jIYdiRH2XLyYFbPxqw2D209+Hd0OqoPMc/LiDFs7PETpvr+aJY2\r\nbyJDKljhEwv2i45wSTd+BLmaILVw6k3AnWoQkwIDAQABAoIBAGhDMqLEepABoMzS\r\ngjKQ2fUiwdDmWzmWYT/Jp3f75jrz2T+VSJ2ey6fuqUdYRunOSoYLiL18K5DJqSHV\r\nbG6OI8OVPTDBzb/hhSur4MgSXH8X5pb/2USM8yo05AsPkGpXKIn6jIiPWOWaSJkb\r\n47KOkKt/tssDLvLMuH+J0gGs+aD0vU9iz4sSq3RkhYx+f9AgAGS/gamlFA8i6onJ\r\ncw/JhC2BygYHZ2oSO58i8/jsv/XQP9sy1OOYjMH715ZuMA4g4B/2re/ttO9Hc9L/\r\nq99PphSIjSUqpQGeQnZJ0WLG//pMkM7eQQgpigjln5pGoiQd5jhpHIB/aAvPp6oC\r\nTbjvPZECgYEA72OnEmC2A882DYM3gqsKaf8s+kTk8wcdsrinTNnRIoiZ8ncaXsHe\r\ngalPYsfubogf8LvSEJ4O0pzXGVE/mQBj9IG81fGoXP9KNu2Rj9Bbe6VAjeAW7RlO\r\ngzD9MU0Ail9cPEorczl3ZfL9+rlQP9eAdheUEAxIILjC8UVnFkdrWXkCgYEAqeww\r\nrXhTTJf1X7zYBJHysstwQutBLPqjSRFzz64evTF3EtoWdEwcHZIdh9bg5Tgl0gFY\r\n1b3gUtIawWL0Yi7cutwwKlDsuyzcvVyNC18O3phZhNOH0LvHQq6U4guaxZOgMTx9\r\n2UNnWuglQPHqjMuRqcozp7rCEE8njLB30hzpQ2sCgYEAhzw1ouUtjgNeFs4c6t1z\r\nOaQlJZEMAdrwRQmZwYl/YtHmnhn4tLUy3O7n4PbvVFPkL1v7dNXFq+dcgHnswqN8\r\n1CECq54kLb0ukM8unx7mv3gAeuWwLetQ9j4TmulUN9ddRNXlq+c380kNf7l2g0pb\r\n0NrLEzHNAWc/AYvii6x3EYkCgYARU9eG6P09k0VfVOeGV8ey+dHh0RGdX5WlDtWL\r\neQsDafblgj3F8DjxvwOp5Xybg0VADAkeCrXEXE6EJ+4Z0QOLPobe2c+6KpH78WMk\r\npLXkdw6x38w6udtQ7nKaNmq6+Rndy3hd3mS8vW2HGOQ9JUkeUlNAKGg/t4Kl8xzU\r\n3UPgLwKBgQCaoOYxGrIsfvQa/qZHfj5e6Y/JsGPHwBNVJzOLeU6sW8TVOFdDrJCz\r\nwGBuSqbm3NipwUSvWrLvefxIHGrLVlFPWBEfv2ignwTEMEu4P0upon8OEZKzDZnl\r\nns/zM0F8YG+q5NcelLgETd5Bxd43+SqL9jIyBs9W/M6FYKyo/xkZFw==\r\n-----END RSA PRIVATE KEY-----\r\n\r\n";


int mbedtls_pk_load_file( const char *path, unsigned char **buf, size_t *n )
{

     if( strstr( path, "cert.pem" ) != NULL ){
	*buf = malloc(strlen(cert_pem)+1);
	strcpy((char *)*buf , (const char *)cert_pem);
	*n = (size_t)sizeof(cert_pem);
    }
    else if( strstr( path, "aws-iot-rootCA.crt" ) != NULL ){
	*buf = malloc(strlen(rootCA_crt)+1);
	strcpy((char *)*buf , (const char *)rootCA_crt);
	*n = (size_t)sizeof(rootCA_crt);
    }
    else if( strstr( path, "privkey.pem" ) != NULL ){
	*buf = malloc(strlen(privkey_pem)+1);
	strcpy((char *)*buf , (const char *)privkey_pem);
	*n = (size_t)sizeof(privkey_pem);
    }
    return( 0 );
}

/*
 * Load and parse a private key
 */
int mbedtls_pk_parse_keyfile( mbedtls_pk_context *ctx,
                      const char *path, const char *pwd )
{
    int ret;
    size_t n;
    unsigned char *buf;
	
    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    if( pwd == NULL )
        ret = mbedtls_pk_parse_key( ctx, buf, n, NULL, 0 );
    else
        ret = mbedtls_pk_parse_key( ctx, buf, n,
                (const unsigned char *) pwd, strlen( pwd ) );

    mbedtls_zeroize( buf, n );
    mbedtls_free( buf );

    return( 0 );
}

/*
 * Load and parse a public key
 */
int mbedtls_pk_parse_public_keyfile( mbedtls_pk_context *ctx, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_pk_parse_public_key( ctx, buf, n );

    mbedtls_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

#if defined(MBEDTLS_ECP_C)
/* Minimally parse an ECParameters buffer to and mbedtls_asn1_buf
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 * }
 */
static int pk_get_ecparams( unsigned char **p, const unsigned char *end,
                            mbedtls_asn1_buf *params )
{
    int ret;

    /* Tag may be either OID or SEQUENCE */
    params->tag = **p;
    if( params->tag != MBEDTLS_ASN1_OID
#if defined(MBEDTLS_PK_PARSE_EC_EXTENDED)
            && params->tag != ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE )
#endif
            )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
    }

    if( ( ret = mbedtls_asn1_get_tag( p, end, &params->len, params->tag ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    params->p = *p;
    *p += params->len;

    if( *p != end )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

#if defined(MBEDTLS_PK_PARSE_EC_EXTENDED)
/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and (mostly) fill the group with it.
 * WARNING: the resulting group should only be used with
 * pk_group_id_from_specified(), since its base point may not be set correctly
 * if it was encoded compressed.
 *
 *  SpecifiedECDomain ::= SEQUENCE {
 *      version SpecifiedECDomainVersion(ecdpVer1 | ecdpVer2 | ecdpVer3, ...),
 *      fieldID FieldID {{FieldTypes}},
 *      curve Curve,
 *      base ECPoint,
 *      order INTEGER,
 *      cofactor INTEGER OPTIONAL,
 *      hash HashAlgorithm OPTIONAL,
 *      ...
 *  }
 *
 * We only support prime-field as field type, and ignore hash and cofactor.
 */
static int pk_group_from_specified( const mbedtls_asn1_buf *params, mbedtls_ecp_group *grp )
{
    int ret;
    unsigned char *p = params->p;
    const unsigned char * const end = params->p + params->len;
    const unsigned char *end_field, *end_curve;
    size_t len;
    int ver;

    /* SpecifiedECDomainVersion ::= INTEGER { 1, 2, 3 } */
    if( ( ret = mbedtls_asn1_get_int( &p, end, &ver ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ver < 1 || ver > 3 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );

    /*
     * FieldID { FIELD-ID:IOSet } ::= SEQUENCE { -- Finite field
     *       fieldType FIELD-ID.&id({IOSet}),
     *       parameters FIELD-ID.&Type({IOSet}{@fieldType})
     * }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    end_field = p + len;

    /*
     * FIELD-ID ::= TYPE-IDENTIFIER
     * FieldTypes FIELD-ID ::= {
     *       { Prime-p IDENTIFIED BY prime-field } |
     *       { Characteristic-two IDENTIFIED BY characteristic-two-field }
     * }
     * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end_field, &len, MBEDTLS_ASN1_OID ) ) != 0 )
        return( ret );

    if( len != MBEDTLS_OID_SIZE( MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD ) ||
        memcmp( p, MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD, len ) != 0 )
    {
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
    }

    p += len;

    /* Prime-p ::= INTEGER -- Field of size p. */
    if( ( ret = mbedtls_asn1_get_mpi( &p, end_field, &grp->P ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    grp->pbits = mbedtls_mpi_bitlen( &grp->P );

    if( p != end_field )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * Curve ::= SEQUENCE {
     *       a FieldElement,
     *       b FieldElement,
     *       seed BIT STRING OPTIONAL
     *       -- Shall be present if used in SpecifiedECDomain
     *       -- with version equal to ecdpVer2 or ecdpVer3
     * }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    end_curve = p + len;

    /*
     * FieldElement ::= OCTET STRING
     * containing an integer in the case of a prime field
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end_curve, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 ||
        ( ret = mbedtls_mpi_read_binary( &grp->A, p, len ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    p += len;

    if( ( ret = mbedtls_asn1_get_tag( &p, end_curve, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 ||
        ( ret = mbedtls_mpi_read_binary( &grp->B, p, len ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    p += len;

    /* Ignore seed BIT STRING OPTIONAL */
    if( ( ret = mbedtls_asn1_get_tag( &p, end_curve, &len, MBEDTLS_ASN1_BIT_STRING ) ) == 0 )
        p += len;

    if( p != end_curve )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * ECPoint ::= OCTET STRING
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = mbedtls_ecp_point_read_binary( grp, &grp->G,
                                      ( const unsigned char *) p, len ) ) != 0 )
    {
        /*
         * If we can't read the point because it's compressed, cheat by
         * reading only the X coordinate and the parity bit of Y.
         */
        if( ret != MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ||
            ( p[0] != 0x02 && p[0] != 0x03 ) ||
            len != mbedtls_mpi_size( &grp->P ) + 1 ||
            mbedtls_mpi_read_binary( &grp->G.X, p + 1, len - 1 ) != 0 ||
            mbedtls_mpi_lset( &grp->G.Y, p[0] - 2 ) != 0 ||
            mbedtls_mpi_lset( &grp->G.Z, 1 ) != 0 )
        {
            return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
        }
    }

    p += len;

    /*
     * order INTEGER
     */
    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &grp->N ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    grp->nbits = mbedtls_mpi_bitlen( &grp->N );

    /*
     * Allow optional elements by purposefully not enforcing p == end here.
     */

    return( 0 );
}

/*
 * Find the group id associated with an (almost filled) group as generated by
 * pk_group_from_specified(), or return an error if unknown.
 */
static int pk_group_id_from_group( const mbedtls_ecp_group *grp, mbedtls_ecp_group_id *grp_id )
{
    int ret = 0;
    mbedtls_ecp_group ref;
    const mbedtls_ecp_group_id *id;

    mbedtls_ecp_group_init( &ref );

    for( id = mbedtls_ecp_grp_id_list(); *id != MBEDTLS_ECP_DP_NONE; id++ )
    {
        /* Load the group associated to that id */
        mbedtls_ecp_group_free( &ref );
        MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ref, *id ) );

        /* Compare to the group we were given, starting with easy tests */
        if( grp->pbits == ref.pbits && grp->nbits == ref.nbits &&
            mbedtls_mpi_cmp_mpi( &grp->P, &ref.P ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->A, &ref.A ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->B, &ref.B ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->N, &ref.N ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->G.X, &ref.G.X ) == 0 &&
            mbedtls_mpi_cmp_mpi( &grp->G.Z, &ref.G.Z ) == 0 &&
            /* For Y we may only know the parity bit, so compare only that */
            mbedtls_mpi_get_bit( &grp->G.Y, 0 ) == mbedtls_mpi_get_bit( &ref.G.Y, 0 ) )
        {
            break;
        }

    }

cleanup:
    mbedtls_ecp_group_free( &ref );

    *grp_id = *id;

    if( ret == 0 && *id == MBEDTLS_ECP_DP_NONE )
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    return( ret );
}

/*
 * Parse a SpecifiedECDomain (SEC 1 C.2) and find the associated group ID
 */
static int pk_group_id_from_specified( const mbedtls_asn1_buf *params,
                                       mbedtls_ecp_group_id *grp_id )
{
    int ret;
    mbedtls_ecp_group grp;

    mbedtls_ecp_group_init( &grp );

    if( ( ret = pk_group_from_specified( params, &grp ) ) != 0 )
        goto cleanup;

    ret = pk_group_id_from_group( &grp, grp_id );

cleanup:
    mbedtls_ecp_group_free( &grp );

    return( ret );
}
#endif /* MBEDTLS_PK_PARSE_EC_EXTENDED */

/*
 * Use EC parameters to initialise an EC group
 *
 * ECParameters ::= CHOICE {
 *   namedCurve         OBJECT IDENTIFIER
 *   specifiedCurve     SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 */
static int pk_use_ecparams( const mbedtls_asn1_buf *params, mbedtls_ecp_group *grp )
{
    int ret;
    mbedtls_ecp_group_id grp_id;

    if( params->tag == MBEDTLS_ASN1_OID )
    {
        if( mbedtls_oid_get_ec_grp( params, &grp_id ) != 0 )
            return( MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE );
    }
    else
    {
#if defined(MBEDTLS_PK_PARSE_EC_EXTENDED)
        if( ( ret = pk_group_id_from_specified( params, &grp_id ) ) != 0 )
            return( ret );
#else
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
#endif
    }

    /*
     * grp may already be initilialized; if so, make sure IDs match
     */
    if( grp->id != MBEDTLS_ECP_DP_NONE && grp->id != grp_id )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );

    if( ( ret = mbedtls_ecp_group_load( grp, grp_id ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * EC public key is an EC point
 *
 * The caller is responsible for clearing the structure upon failure if
 * desired. Take care to pass along the possible ECP_FEATURE_UNAVAILABLE
 * return code of mbedtls_ecp_point_read_binary() and leave p in a usable state.
 */
static int pk_get_ecpubkey( unsigned char **p, const unsigned char *end,
                            mbedtls_ecp_keypair *key )
{
    int ret;

    if( ( ret = mbedtls_ecp_point_read_binary( &key->grp, &key->Q,
                    (const unsigned char *) *p, end - *p ) ) == 0 )
    {
        ret = mbedtls_ecp_check_pubkey( &key->grp, &key->Q );
    }

    /*
     * We know mbedtls_ecp_point_read_binary consumed all bytes or failed
     */
    *p = (unsigned char *) end;

    return( ret );
}
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_RSA_C)
/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_get_rsapubkey( unsigned char **p,
                             const unsigned char *end,
                             mbedtls_rsa_context *rsa )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( ret = mbedtls_asn1_get_mpi( p, end, &rsa->N ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( p, end, &rsa->E ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( ret = mbedtls_rsa_check_pubkey( rsa ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY );

    rsa->len = mbedtls_mpi_size( &rsa->N );

    return( 0 );
}
#endif /* MBEDTLS_RSA_C */

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg( unsigned char **p,
                          const unsigned char *end,
                          mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params )
{
    int ret;
    mbedtls_asn1_buf alg_oid;

    memset( params, 0, sizeof(mbedtls_asn1_buf) );

    if( ( ret = mbedtls_asn1_get_alg( p, end, &alg_oid, params ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_ALG + ret );

    if( mbedtls_oid_get_pk_alg( &alg_oid, pk_alg ) != 0 )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    /*
     * No parameters with RSA (only for EC)
     */
    if( *pk_alg == MBEDTLS_PK_RSA &&
            ( ( params->tag != MBEDTLS_ASN1_NULL && params->tag != 0 ) ||
                params->len != 0 ) )
    {
        return( MBEDTLS_ERR_PK_INVALID_ALG );
    }

    return( 0 );
}

/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int mbedtls_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        mbedtls_pk_context *pk )
{
    int ret;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = pk_get_pk_alg( p, end, &pk_alg, &alg_params ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( pk_info = mbedtls_pk_info_from_type( pk_alg ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA )
    {
        ret = pk_get_rsapubkey( p, end, mbedtls_pk_rsa( *pk ) );
    } else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
    if( pk_alg == MBEDTLS_PK_ECKEY_DH || pk_alg == MBEDTLS_PK_ECKEY )
    {
        ret = pk_use_ecparams( &alg_params, &mbedtls_pk_ec( *pk )->grp );
        if( ret == 0 )
            ret = pk_get_ecpubkey( p, end, mbedtls_pk_ec( *pk ) );
    } else
#endif /* MBEDTLS_ECP_C */
        ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;

    if( ret == 0 && *p != end )
        ret = MBEDTLS_ERR_PK_INVALID_PUBKEY
              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    if( ret != 0 )
        mbedtls_pk_free( pk );

    return( ret );
}

#if defined(MBEDTLS_RSA_C)
/*
 * Parse a PKCS#1 encoded private RSA key
 */
static int pk_parse_key_pkcs1_der( mbedtls_rsa_context *rsa,
                                   const unsigned char *key,
                                   size_t keylen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;

    p = (unsigned char *) key;
    end = p + keylen;

    /*
     * This function parses the RSAPrivateKey (PKCS#1)
     *
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &rsa->ver ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    if( rsa->ver != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_VERSION );
    }

    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->N  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->E  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->D  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->P  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->Q  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->DP ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->DQ ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->QP ) ) != 0 )
    {
        mbedtls_rsa_free( rsa );
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    rsa->len = mbedtls_mpi_size( &rsa->N );

    if( p != end )
    {
        mbedtls_rsa_free( rsa );
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = mbedtls_rsa_check_privkey( rsa ) ) != 0 )
    {
        mbedtls_rsa_free( rsa );
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * Parse a SEC1 encoded private EC key
 */
static int pk_parse_key_sec1_der( mbedtls_ecp_keypair *eck,
                                  const unsigned char *key,
                                  size_t keylen )
{
    int ret;
    int version, pubkey_done;
    size_t len;
    mbedtls_asn1_buf params;
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = p + keylen;
    unsigned char *end2;

    /*
     * RFC 5915, or SEC1 Appendix C.4
     *
     * ECPrivateKey ::= SEQUENCE {
     *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *      privateKey     OCTET STRING,
     *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *      publicKey  [1] BIT STRING OPTIONAL
     *    }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &version ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( version != 1 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_VERSION );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = mbedtls_mpi_read_binary( &eck->d, p, len ) ) != 0 )
    {
        mbedtls_ecp_keypair_free( eck );
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    p += len;

    pubkey_done = 0;
    if( p != end )
    {
        /*
         * Is 'parameters' present?
         */
        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) == 0 )
        {
            if( ( ret = pk_get_ecparams( &p, p + len, &params) ) != 0 ||
                ( ret = pk_use_ecparams( &params, &eck->grp )  ) != 0 )
            {
                mbedtls_ecp_keypair_free( eck );
                return( ret );
            }
        }
        else if( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            mbedtls_ecp_keypair_free( eck );
            return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
        }

        /*
         * Is 'publickey' present? If not, or if we can't read it (eg because it
         * is compressed), create it from the private key.
         */
        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1 ) ) == 0 )
        {
            end2 = p + len;

            if( ( ret = mbedtls_asn1_get_bitstring_null( &p, end2, &len ) ) != 0 )
                return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

            if( p + len != end2 )
                return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                        MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

            if( ( ret = pk_get_ecpubkey( &p, end2, eck ) ) == 0 )
                pubkey_done = 1;
            else
            {
                /*
                 * The only acceptable failure mode of pk_get_ecpubkey() above
                 * is if the point format is not recognized.
                 */
                if( ret != MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE )
                    return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
            }
        }
        else if( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            mbedtls_ecp_keypair_free( eck );
            return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
        }
    }

    if( ! pubkey_done &&
        ( ret = mbedtls_ecp_mul( &eck->grp, &eck->Q, &eck->d, &eck->grp.G,
                                                      NULL, NULL ) ) != 0 )
    {
        mbedtls_ecp_keypair_free( eck );
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    if( ( ret = mbedtls_ecp_check_privkey( &eck->grp, &eck->d ) ) != 0 )
    {
        mbedtls_ecp_keypair_free( eck );
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_ECP_C */

/*
 * Parse an unencrypted PKCS#8 encoded private key
 */
static int pk_parse_key_pkcs8_unencrypted_der(
                                    mbedtls_pk_context *pk,
                                    const unsigned char* key,
                                    size_t keylen )
{
    int ret, version;
    size_t len;
    mbedtls_asn1_buf params;
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = p + keylen;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    /*
     * This function parses the PrivatKeyInfo object (PKCS#8 v1.2 = RFC 5208)
     *
     *    PrivateKeyInfo ::= SEQUENCE {
     *      version                   Version,
     *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *      privateKey                PrivateKey,
     *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
     *
     *    Version ::= INTEGER
     *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *    PrivateKey ::= OCTET STRING
     *
     *  The PrivateKey OCTET STRING is a SEC1 ECPrivateKey
     */

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &version ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( version != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_VERSION + ret );

    if( ( ret = pk_get_pk_alg( &p, end, &pk_alg, &params ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( len < 1 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( ( pk_info = mbedtls_pk_info_from_type( pk_alg ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA )
    {
        if( ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ), p, len ) ) != 0 )
        {
            mbedtls_pk_free( pk );
            return( ret );
        }
    } else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
    if( pk_alg == MBEDTLS_PK_ECKEY || pk_alg == MBEDTLS_PK_ECKEY_DH )
    {
        if( ( ret = pk_use_ecparams( &params, &mbedtls_pk_ec( *pk )->grp ) ) != 0 ||
            ( ret = pk_parse_key_sec1_der( mbedtls_pk_ec( *pk ), p, len )  ) != 0 )
        {
            mbedtls_pk_free( pk );
            return( ret );
        }
    } else
#endif /* MBEDTLS_ECP_C */
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    return( 0 );
}

/*
 * Parse an encrypted PKCS#8 encoded private key
 */
#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
static int pk_parse_key_pkcs8_encrypted_der(
                                    mbedtls_pk_context *pk,
                                    const unsigned char *key, size_t keylen,
                                    const unsigned char *pwd, size_t pwdlen )
{
    int ret, decrypted = 0;
    size_t len;
    unsigned char buf[2048];
    unsigned char *p, *end;
    mbedtls_asn1_buf pbe_alg_oid, pbe_params;
#if defined(MBEDTLS_PKCS12_C)
    mbedtls_cipher_type_t cipher_alg;
    mbedtls_md_type_t md_alg;
#endif

    memset( buf, 0, sizeof( buf ) );

    p = (unsigned char *) key;
    end = p + keylen;

    if( pwdlen == 0 )
        return( MBEDTLS_ERR_PK_PASSWORD_REQUIRED );

    /*
     * This function parses the EncryptedPrivatKeyInfo object (PKCS#8)
     *
     *  EncryptedPrivateKeyInfo ::= SEQUENCE {
     *    encryptionAlgorithm  EncryptionAlgorithmIdentifier,
     *    encryptedData        EncryptedData
     *  }
     *
     *  EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
     *
     *  EncryptedData ::= OCTET STRING
     *
     *  The EncryptedData OCTET STRING is a PKCS#8 PrivateKeyInfo
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_alg( &p, end, &pbe_alg_oid, &pbe_params ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( len > sizeof( buf ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    /*
     * Decrypt EncryptedData with appropriate PDE
     */
#if defined(MBEDTLS_PKCS12_C)
    if( mbedtls_oid_get_pkcs12_pbe_alg( &pbe_alg_oid, &md_alg, &cipher_alg ) == 0 )
    {
        if( ( ret = mbedtls_pkcs12_pbe( &pbe_params, MBEDTLS_PKCS12_PBE_DECRYPT,
                                cipher_alg, md_alg,
                                pwd, pwdlen, p, len, buf ) ) != 0 )
        {
            if( ret == MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH )
                return( MBEDTLS_ERR_PK_PASSWORD_MISMATCH );

            return( ret );
        }

        decrypted = 1;
    }
    else if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS12_PBE_SHA1_RC4_128, &pbe_alg_oid ) == 0 )
    {
        if( ( ret = mbedtls_pkcs12_pbe_sha1_rc4_128( &pbe_params,
                                             MBEDTLS_PKCS12_PBE_DECRYPT,
                                             pwd, pwdlen,
                                             p, len, buf ) ) != 0 )
        {
            return( ret );
        }

        // Best guess for password mismatch when using RC4. If first tag is
        // not MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE
        //
        if( *buf != ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) )
            return( MBEDTLS_ERR_PK_PASSWORD_MISMATCH );

        decrypted = 1;
    }
    else
#endif /* MBEDTLS_PKCS12_C */
#if defined(MBEDTLS_PKCS5_C)
    if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS5_PBES2, &pbe_alg_oid ) == 0 )
    {
        if( ( ret = mbedtls_pkcs5_pbes2( &pbe_params, MBEDTLS_PKCS5_DECRYPT, pwd, pwdlen,
                                  p, len, buf ) ) != 0 )
        {
            if( ret == MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH )
                return( MBEDTLS_ERR_PK_PASSWORD_MISMATCH );

            return( ret );
        }

        decrypted = 1;
    }
    else
#endif /* MBEDTLS_PKCS5_C */
    {
        ((void) pwd);
    }

    if( decrypted == 0 )
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    return( pk_parse_key_pkcs8_unencrypted_der( pk, buf, len ) );
}
#endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */

/*
 * Parse a private key
 */
int mbedtls_pk_parse_key( mbedtls_pk_context *pk,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen )
{
    int ret;
    const mbedtls_pk_info_t *pk_info;

#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;

    mbedtls_pem_init( &pem );

#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN RSA PRIVATE KEY-----",
                               "-----END RSA PRIVATE KEY-----",
                               key, pwd, pwdlen, &len );

    if( ret == 0 )
    {
        if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == NULL )
            return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

        if( ( ret = mbedtls_pk_setup( pk, pk_info                    ) ) != 0 ||
            ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ),
                                            pem.buf, pem.buflen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH )
        return( MBEDTLS_ERR_PK_PASSWORD_MISMATCH );
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED )
        return( MBEDTLS_ERR_PK_PASSWORD_REQUIRED );
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN EC PRIVATE KEY-----",
                               "-----END EC PRIVATE KEY-----",
                               key, pwd, pwdlen, &len );
    if( ret == 0 )
    {
        if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) == NULL )
            return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

        if( ( ret = mbedtls_pk_setup( pk, pk_info                   ) ) != 0 ||
            ( ret = pk_parse_key_sec1_der( mbedtls_pk_ec( *pk ),
                                           pem.buf, pem.buflen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH )
        return( MBEDTLS_ERR_PK_PASSWORD_MISMATCH );
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED )
        return( MBEDTLS_ERR_PK_PASSWORD_REQUIRED );
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* MBEDTLS_ECP_C */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN PRIVATE KEY-----",
                               "-----END PRIVATE KEY-----",
                               key, NULL, 0, &len );
    if( ret == 0 )
    {
        if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk,
                                                pem.buf, pem.buflen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );

#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                               "-----END ENCRYPTED PRIVATE KEY-----",
                               key, NULL, 0, &len );
    if( ret == 0 )
    {
        if( ( ret = pk_parse_key_pkcs8_encrypted_der( pk,
                                                      pem.buf, pem.buflen,
                                                      pwd, pwdlen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */
#else
    ((void) pwd);
    ((void) pwdlen);
#endif /* MBEDTLS_PEM_PARSE_C */

    /*
    * At this point we only know it's not a PEM formatted key. Could be any
    * of the known DER encoded private key formats
    *
    * We try the different DER format parsers to see if one passes without
    * error
    */
#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    if( ( ret = pk_parse_key_pkcs8_encrypted_der( pk, key, keylen,
                                                  pwd, pwdlen ) ) == 0 )
    {
        return( 0 );
    }

    mbedtls_pk_free( pk );

    if( ret == MBEDTLS_ERR_PK_PASSWORD_MISMATCH )
    {
        return( ret );
    }
#endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */

    if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk, key, keylen ) ) == 0 )
        return( 0 );

    mbedtls_pk_free( pk );

#if defined(MBEDTLS_RSA_C)
    if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info                           ) ) != 0 ||
        ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ), key, keylen ) ) == 0 )
    {
        return( 0 );
    }

    mbedtls_pk_free( pk );
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
    if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info                         ) ) != 0 ||
        ( ret = pk_parse_key_sec1_der( mbedtls_pk_ec( *pk ), key, keylen ) ) == 0 )
    {
        return( 0 );
    }

    mbedtls_pk_free( pk );
#endif /* MBEDTLS_ECP_C */

    return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
}

/*
 * Parse a public key
 */
int mbedtls_pk_parse_public_key( mbedtls_pk_context *ctx,
                         const unsigned char *key, size_t keylen )
{
    int ret;
    unsigned char *p;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;

    mbedtls_pem_init( &pem );

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                "-----BEGIN PUBLIC KEY-----",
                "-----END PUBLIC KEY-----",
                key, NULL, 0, &len );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded
         */
        key = pem.buf;
        keylen = pem.buflen;
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        mbedtls_pem_free( &pem );
        return( ret );
    }
#endif /* MBEDTLS_PEM_PARSE_C */
    p = (unsigned char *) key;

    ret = mbedtls_pk_parse_subpubkey( &p, p + keylen, ctx );

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_free( &pem );
#endif

    return( ret );
}

#endif /* MBEDTLS_PK_PARSE_C */
