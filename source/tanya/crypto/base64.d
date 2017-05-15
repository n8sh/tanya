/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.crypto.base64;

import core.stdc.stdio;

private string base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const(char)* input, int len, char* output)
{
    do
    {
        *output++ = base64[ ( input[ 0 ] & 0xFC ) >> 2 ];

        if ( len == 1 )
        {
            *output++ = base64[((input[0] & 0x03) << 4)];
            *output++ = '=';
            *output++ = '=';
            break;
        }

        *output++ = base64[((input[0] & 0x03 ) << 4 ) | ((input[1] & 0xF0 ) >> 4)];

        if ( len == 2 )
        {
            *output++ = base64[((input[ 1 ] & 0x0F) << 2)];
            *output++ = '=';
            break;
        }

        *output++ = base64[
            ((input[1] & 0x0F) << 2) | ((input[2] & 0xC0) >> 6)];
        *output++ = base64[(input[2] & 0x3F)];
        input += 3;
    }
    while (len -= 3);

    *output = '\0';
}

private int[] unbase64 = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52,
    53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 0, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
    42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1
];

int base64_decode(const(char)* input, int len, char* output)
{
    int out_len = 0, i;
    assert(!(len & 0x03)); // Is an even multiple of 4

    do
    {
        for (i = 0; i <= 3; i++)
        {
            // Check for illegal base64 characters
            if ( input[ i ] > 128 || unbase64[ input[ i ] ] == -1 )
            {
                fprintf(stderr, "invalid character for base64 encoding: %c\n",
                    input[i]);
                return -1;
            }
        }
        *output++ = cast(char) (unbase64[input[0]] << 2 |
            (unbase64[input[1]] & 0x30) >> 4);
        out_len++;
        if (input[2] != '=')
        {
            *output++ = (unbase64[input[1]] & 0x0F) << 4 |
                (unbase64[input[2]] & 0x3C) >> 2;
            out_len++;
        }

        if (input[3] != '=')
        {
            *output++ = cast(char) ((unbase64[input[2]] & 0x03) << 6 |
                unbase64[input[3]]);
            out_len++;
        }
        input += 4;
    }
    while (len -= 4);
    return out_len;
}
