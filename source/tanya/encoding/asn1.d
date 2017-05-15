/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Abstract Syntax Notation One.
 *
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.encoding.asn1;

import tanya.crypto.base64;
import core.stdc.string;
import core.stdc.stdlib;
import core.stdc.stdio;

struct asn1struct
{
    bool constructed; // bit 6 of the identifier byte
    TagClass tagClass; // bits 7-8 of the identifiery byte
    int tag; // bits 1-5 of the identifier byte
    int length;
    const(ubyte)* data;
    asn1struct* children;
    asn1struct* next;
}

enum TagClass
{
    universal = 0,
    application = 1,
    contextSpecific = 2,
    private_ = 3,
}

enum TagType
{
    ber = 0,
    boolean = 1,
    integer = 2,
    bitString = 3,
    octetString = 4,
    null_ = 5,
    objectIdentifier = 6,
    objectDescriptor = 7,
    instanceOfExternal = 8,
    real_ = 9,
    enumerated = 10,
    embeddedPPV = 11,
    utf8String = 12,
    relativeOID = 13,
    // 14 and 15 are undefined.
    sequence = 16,
    set = 17,
    numericString = 18,
    printableString = 19,
    teletexString = 20,
    videotexString = 21,
    ia5String = 22,
    utcTime = 23,
    generalizedTime = 24,
    graphicString = 25,
    visibleString = 26,
    generalString = 27,
    universalString = 28,
    characterString = 29,
    bmpString = 30,
}

int asn1parse(const ubyte* buffer, int length, asn1struct* top_level_token)
{
    uint tag;
    ubyte tag_length_byte;
    ulong tag_length;
    const(ubyte)* ptr = buffer;
    const(ubyte)* ptr_begin;
    asn1struct* token = top_level_token;

    while (length)
    {
        ptr_begin = ptr;
        tag = *ptr;
        ptr++;
        length--;

        // High tag # form (bits 5-1 all == "1"), to encode tags > 31. Not used
        // in X.509
        if ((tag & 0x1f) == 0x1f)
        {
            tag = 0;
            while (*ptr & 0x80)
            {
                tag <<= 8;
                tag |= *ptr & 0x7f;
            }
        }

        tag_length_byte = *ptr;
        ptr++;
        length--;

        // TODO this doesn't handle indefinite-length encodings (according to
        // ITU-T X.690, this never occurs in DER, only in BER, which X.509 doesn't
        // use)
        if (tag_length_byte & 0x80)
        {
            const(ubyte)* len_ptr = ptr;
            tag_length = 0;
            while ((len_ptr - ptr) < (tag_length_byte & 0x7f))
            {
                tag_length <<= 8;
                tag_length |= *(len_ptr++);
                length--;
            }
            ptr = len_ptr;
        }
        else
        {
            tag_length = tag_length_byte;
        }

        // TODO deal with "high tag numbers"
        token.constructed = (tag & 0x20) != 0;
        token.tagClass = cast(TagClass) ((tag & 0xc0) >> 6);
        token.tag = tag & 0x1f;
        token.length = cast(int) tag_length;
        token.data = ptr;
        token.children = null;
        token.next = null;

        if (tag & 0x20)
        {
            token.length = cast(int) (tag_length + (ptr - ptr_begin));

            token.data = ptr_begin;

            // Append a child to this tag and recurse into it
            token.children = cast(asn1struct*) malloc(asn1struct.sizeof);
            asn1parse(ptr, cast(int) tag_length, token.children);
        }

        ptr += tag_length;
        length -= tag_length;

        // At this point, we're pointed at the tag for the next token in the buffer.
        if (length)
        {
            token.next = cast(asn1struct*) malloc(asn1struct.sizeof);
            token = token.next;
        }
    }

    return 0;
}

/**
 * Recurse through the given node and free all of the memory that was allocated
 * by asn1parse. Don't free the "data" pointers, since that points to memory that
 * was not allocated by asn1parse.
 */
void asn1free(asn1struct* node)
{
    if (!node )
    {
        return;
    }

    asn1free(node.children);
    free(node.children);
    asn1free(node.next);
    free(node.next);
}

int pem_decode(ubyte* pem_buffer, ubyte* der_buffer)
{
    ubyte* pem_buffer_end, pem_buffer_begin;
    ubyte* bufptr = der_buffer;
    int buffer_size;
    // Skip first line, which is always "-----BEGIN CERTIFICATE-----".

    if (strncmp(cast(char*) pem_buffer, "-----BEGIN", 10))
    {
        fprintf(core.stdc.stdio.stderr, "This does not appear to be a PEM-encoded certificate file\n");
        exit(0);
    }

    pem_buffer_begin = pem_buffer;
    pem_buffer = pem_buffer_end = cast(ubyte*) strchr(cast(char*) pem_buffer, '\n') + 1;

    while (strncmp(cast(char*) pem_buffer, "-----END", 8))
    {
        // Find end of line
        pem_buffer_end = cast(ubyte*) strchr(cast(char*) pem_buffer, '\n');
        // Decode one line out of pem_buffer int buffer
        bufptr += base64_decode(cast(char*) pem_buffer,
                cast(int) (pem_buffer_end - pem_buffer) -
                ((*(pem_buffer_end - 1) == '\r') ? 1 : 0),
                cast(char*) bufptr);
        pem_buffer = pem_buffer_end + 1;
    }

    buffer_size = cast(int) (bufptr - der_buffer);

    return buffer_size;
}
