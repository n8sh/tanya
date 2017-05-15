/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.crypto.rsa;

import core.stdc.string;
import core.stdc.stdlib;
import core.stdc.stdio;
import std.algorithm.mutation;
import tanya.math;

struct rsa_key
{
    Integer modulus;
    Integer exponent;
}

/**
 * Compute c = m^e mod n.
 */
private void rsa_compute(ref Integer m, ref Integer e, ref Integer n, ref Integer c)
{
    Integer counter;
    Integer one;

    c = m;
    counter = 1;
    one = 1;
    while (counter < e)
    {
        c *= m;
        counter += one;
    }

    c %= n;
}

/**
 * The input should be broken up into n-bit blocks, where n is the
 * length in bits of the modulus. The output will always be n bits
 * or less. Per RFC 2313, there must be at least 8 bytes of padding
 * to prevent an attacker from trying all possible padding bytes.
 *
 * output will be allocated by this routine, must be freed by the
 * caller.
 *
 * returns the length of the data encrypted in output
 */
ubyte[] rsa_process(ubyte[] input,
                    ref rsa_key public_key,
                    ubyte block_type)
{
    const modulusLength = public_key.modulus.length - 1;
    size_t block_size;
    auto padded_block = cast(ubyte[]) malloc(modulusLength)[0 .. modulusLength];
    int encrypted_size = 0;
    auto len = input.length;
    auto inp = input.ptr;
    ubyte[] output;

    while (len)
    {
        encrypted_size += modulusLength;
        block_size = (len < modulusLength - 11) ? len : (modulusLength - 11);
        padded_block[] = 0;
        memcpy(padded_block.ptr + (modulusLength - block_size), inp, block_size);
        // set block type
        padded_block[1] = block_type;

        for (size_t i = 2; i < (modulusLength - block_size - 1); ++i)
        {
            if (block_type == 0x02)
            {
                // TODO make these random
                padded_block[i] = cast(ubyte) i;
            }
            else
            {
                padded_block[i] = 0xff;
            }
        }

        auto m = Integer(Sign.positive, padded_block[0 .. modulusLength]);
        auto c = pow(m, public_key.exponent, public_key.modulus);

        output = cast(ubyte[]) realloc(output.ptr, encrypted_size)[0 .. encrypted_size];

        // Unload integer.
        auto source = c.toVector();
        auto target = output.ptr;
        foreach (d; source[])
        {
            *target = d;
            ++target;
        }

        len -= block_size;
        inp += block_size;
    }

    free(padded_block.ptr);

    return output;
}

ubyte[] rsa_encrypt(ubyte[] input, ref rsa_key public_key)
{
    return rsa_process(input, public_key, 0x02);
}

ubyte[] rsa_sign(ubyte[] input, ref rsa_key private_key)
{
    return rsa_process(input, private_key, 0x01);
}

/**
 * Convert the input into key-length blocks and decrypt, unpadding
 * each time.
 * Return -1 if the input is not an even multiple of the key modulus
 * length or if the padding type is not "2", otherwise return the
 * length of the decrypted data.
 */
ubyte[] rsa_decrypt(const(ubyte)[] input, ref rsa_key private_key)
{
    int i, out_len = 0;
    const modulusLength = private_key.modulus.length - 1;
    auto padded_block = cast(ubyte[]) malloc(modulusLength)[0 .. modulusLength];
    auto len = input.length;
    auto inp = input.ptr;
    ubyte[] output;

    while (len)
    {
        if (len < modulusLength)
        {
            fprintf(stderr, "Error - input must be an even multiple of key modulus %d (got %d)\n",
                modulusLength, len);
            free(padded_block.ptr);
            return null;
        }

        auto c = Integer(Sign.positive, inp[0 .. modulusLength]);
        auto m = pow(c, private_key.exponent, private_key.modulus);

        // Unload integer.
        auto source = m.toVector();
        auto target = padded_block.ptr;

        source[].copy(padded_block[padded_block.length - source.length .. $]);

        if (padded_block[1] > 0x02)
        {
            fprintf(stderr, "Decryption error or unrecognized block type %d.\n", padded_block[1]);
            free(padded_block.ptr);
            return null;
        }

        // Find next 0 byte after the padding type byte; this signifies
        // start-of-data
        i = 2;
        while (padded_block[i++])
        {
        }

        out_len += modulusLength - i;
        output = cast(ubyte[]) realloc(output.ptr, out_len)[0 .. out_len];
        memcpy(output.ptr + (out_len - (modulusLength - i)),
               padded_block.ptr + i,
               modulusLength - i);

        len -= modulusLength;
        inp += modulusLength;
    }

    free(padded_block.ptr);

    return output;
}

unittest
{
    const ubyte[] TestModulus = [
        0xC4, 0xF8, 0xE9, 0xE1, 0x5D, 0xCA, 0xDF, 0x2B, 0x96, 0xC7, 0x63, 0xD9, 0x81,
        0x00, 0x6A, 0x64, 0x4F, 0xFB, 0x44, 0x15, 0x03, 0x0A, 0x16, 0xED, 0x12, 0x83,
        0x88, 0x33, 0x40, 0xF2, 0xAA, 0x0E, 0x2B, 0xE2, 0xBE, 0x8F, 0xA6, 0x01, 0x50,
        0xB9, 0x04, 0x69, 0x65, 0x83, 0x7C, 0x3E, 0x7D, 0x15, 0x1B, 0x7D, 0xE2, 0x37,
        0xEB, 0xB9, 0x57, 0xC2, 0x06, 0x63, 0x89, 0x82, 0x50, 0x70, 0x3B, 0x3F
    ];

    const ubyte[] TestPrivateKey = [
        0x8a, 0x7e, 0x79, 0xf3, 0xfb, 0xfe, 0xa8, 0xeb, 0xfd, 0x18, 0x35, 0x1c, 0xb9,
        0x97, 0x91, 0x36, 0xf7, 0x05, 0xb4, 0xd9, 0x11, 0x4a, 0x06, 0xd4, 0xaa, 0x2f,
        0xd1, 0x94, 0x38, 0x16, 0x67, 0x7a, 0x53, 0x74, 0x66, 0x18, 0x46, 0xa3, 0x0c,
        0x45, 0xb3, 0x0a, 0x02, 0x4b, 0x4d, 0x22, 0xb1, 0x5a, 0xb3, 0x23, 0x62, 0x2b,
        0x2d, 0xe4, 0x7b, 0xa2, 0x91, 0x15, 0xf0, 0x6e, 0xe4, 0x2c, 0x41
    ];

    const ubyte[] TestPublicKey = [ 0x01, 0x00, 0x01 ];

    {
        ubyte[] expected = [
            0x40, 0xf7, 0x33, 0x15, 0xd3, 0xf7, 0x47, 0x03, 0x90, 0x4e, 0x51, 0xe1, 0xc7, 0x26, 0x86,
            0x80, 0x1d, 0xe0, 0x6a, 0x55, 0x41, 0x71, 0x10, 0xe5, 0x62, 0x80, 0xf1, 0xf8, 0x47, 0x1a,
            0x38, 0x02, 0x40, 0x6d, 0x21, 0x10, 0x01, 0x1e, 0x1f, 0x38, 0x7f, 0x7b, 0x4c, 0x43, 0x25,
            0x8b, 0x0a, 0x1e, 0xed, 0xc5, 0x58, 0xa3, 0xaa, 0xc5, 0xaa, 0x2d, 0x20, 0xcf, 0x5e, 0x0d,
            0x65, 0xd8, 0x0d, 0xb3
        ];
        ubyte[] data = [ 0x61, 0x62, 0x63 ];

        rsa_key public_key;

        public_key.modulus = Integer(Sign.positive, TestModulus[]);
        public_key.exponent = Integer(Sign.positive, TestPublicKey[]);

        auto encrypted = rsa_encrypt(data, public_key);
        assert(encrypted == expected);
    }
    {
        ubyte[] expected = [ 0x61, 0x62, 0x63 ];
        ubyte[] data = [
            0x40, 0xf7, 0x33, 0x15, 0xd3, 0xf7, 0x47, 0x03, 0x90, 0x4e, 0x51, 0xe1, 0xc7, 0x26, 0x86,
            0x80, 0x1d, 0xe0, 0x6a, 0x55, 0x41, 0x71, 0x10, 0xe5, 0x62, 0x80, 0xf1, 0xf8, 0x47, 0x1a,
            0x38, 0x02, 0x40, 0x6d, 0x21, 0x10, 0x01, 0x1e, 0x1f, 0x38, 0x7f, 0x7b, 0x4c, 0x43, 0x25,
            0x8b, 0x0a, 0x1e, 0xed, 0xc5, 0x58, 0xa3, 0xaa, 0xc5, 0xaa, 0x2d, 0x20, 0xcf, 0x5e, 0x0d,
            0x65, 0xd8, 0x0d, 0xb3
        ];

        rsa_key private_key;

        private_key.modulus = Integer(Sign.positive, TestModulus[]);
        private_key.exponent = Integer(Sign.positive, TestPrivateKey[]);

        auto decrypted = rsa_decrypt(data, private_key);
        assert(decrypted == expected);
    }
}
