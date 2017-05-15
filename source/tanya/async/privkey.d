/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.async.privkey;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import core.sys.posix.arpa.inet;
import tanya.crypto.des;
import tanya.crypto.rsa;
import tanya.encoding.asn1;
import tanya.math.mp;

/**
 * Parse the modulus and private exponent from the buffer, which
 * should contain a DER-encoded RSA private key file.  There's a
 * lot more information in the private key file format, but this
 * app isn't set up to use any of it.
 * This, according to PKCS #1 (note that this is not in pkcs #8 format), is:
 * Version
 * modulus (n)
 * public exponent (e)
 * private exponent (d)
 * prime1 (p)
 * prime2 (q)
 * exponent1 (d mod p-1)
 * exponent2 (d mod q-1)
 * coefficient (inverse of q % p)
 * Here, all we care about is n & d.
 */
int parse_private_key(ref rsa_key privkey, const(ubyte)* buffer, size_t buffer_length)
{
    asn1struct private_key;
    asn1struct* version_;
    asn1struct* modulus;
    asn1struct* public_exponent;
    asn1struct* private_exponent;

    asn1parse(buffer, cast(int) buffer_length, &private_key);

    version_ = cast(asn1struct*) private_key.children;
    modulus = cast(asn1struct*) version_.next;
    // Just read this to skip over it
    public_exponent = cast(asn1struct*) modulus.next;
    private_exponent = cast(asn1struct*) public_exponent.next;

    privkey.modulus = Integer(Sign.positive, modulus.data[0 .. modulus.length]);
    privkey.exponent = Integer(Sign.positive, private_exponent.data[0 .. private_exponent.length]);

    asn1free(&private_key);

    return 0;
}
