/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Interfaces for implementing secret key algorithms.
 *
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.crypto.symmetric;

import tanya.container.array;

// Cipher direction.
enum Direction : ushort
{
    encryption,
    decryption,
}

package void xor(ubyte[] target, in ubyte[] src) pure nothrow @trusted @nogc
in
{
    assert(src.length == target.length);
}
body
{
    auto length = src.length;
    for (auto t = &target[0], s = &src[0]; length > 0; --length)
    {
        *t++ ^= *s++;
    }
}

/**
 * Implemented by secret key algorithms.
 */
interface SymmetricCipher
{
    /**
     * Returns: Key length.
     */
    @property uint keyLength() const pure nothrow @safe @nogc;

    /**
     * Returns: Minimum key length.
     */
    @property uint minKeyLength() const pure nothrow @safe @nogc;

    /**
     * Returns: Maximum key length.
     */
    @property uint maxKeyLength() const pure nothrow @safe @nogc;
}

/**
 * Implemented by block ciphers.
 */
interface BlockCipher : SymmetricCipher
{
    /**
     * Returns: Block size.
     */
    @property uint blockLength() const pure nothrow @safe @nogc;

    /**
     * Encrypts a block.
     *
     * Params:
     *  plain  = Plain text, input.
     *  cipher = Cipher text, output.
     *
     * Precondition: $(D_INLINECODE plain.length == blockLength && cipher.length == blockLength).
     */
    void encrypt(ref const Array!ubyte plain, ref Array!ubyte cipher)
    in
    {
        assert(plain.length == blockLength);
        assert(cipher.length == blockLength);
    }

    /**
     * Decrypts a block.
     *
     * Params:
     *  cipher = Cipher text, input.
     *  plain  = Plain text, output.
     *
     * Precondition: $(D_INLINECODE plain.length == blockLength && cipher.length == blockLength).
     */
    void decrypt(ref const Array!ubyte cipher, ref Array!ubyte plain)
    in
    {
        assert(plain.length == blockLength);
        assert(cipher.length == blockLength);
    }

    /**
     * Resets the key.
     *
     * Params:
     *  key = Key.
     *
     * Precondition: $(D_INLINECODE key.length == this.keyLength).
     */
    @property void key(ref const Array!ubyte key)
    in
    {
        assert(key.length == this.keyLength);
    }
}

/**
 * Mixed in by algorithms with fixed block size.
 *
 * Params:
 *  N = Block size.
 */
mixin template FixedBlockLength(uint N)
    if (N != 0)
{
    private enum uint blockLength_ = N;

    /**
     * Returns: Fixed block size.
     */
    final @property uint blockLength() const pure nothrow @safe @nogc
    {
        return blockLength_;
    }
}

/**
 * Mixed in by symmetric algorithms.
 * If $(D_PARAM Min) equals $(D_PARAM Max) fixed key length is assumed.
 *
 * Params:
 *  Min = Minimum key length.
 *  Max = Maximum key length.
 */
mixin template KeyLength(uint Min, uint Max = Min)
    if (Min != 0 && Max != 0)
{
    static if (Min == Max)
    {
        private enum uint keyLength_ = Min;

        /**
         * Returns: Key length.
         */
        final @property uint keyLength() const pure nothrow @safe @nogc
        {
            return keyLength_;
        }

        /**
         * Returns: Minimum key length.
         */
        final @property uint minKeyLength() const pure nothrow @safe @nogc
        {
            return keyLength_;
        }

        /**
         * Returns: Maximum key length.
         */
        final @property uint maxKeyLength() const pure nothrow @safe @nogc
        {
            return keyLength_;
        }
    }
    else static if (Min < Max)
    {
        private enum uint minKeyLength_ = Min;
        private enum uint maxKeyLength_ = Max;

        /**
         * Returns: Minimum key length.
         */
        final @property uint minKeyLength() const pure nothrow @safe @nogc
        {
            return minKeyLength_;
        }

        /**
         * Returns: Maximum key length.
         */
        final @property uint maxKeyLength() const pure nothrow @safe @nogc
        {
            return maxKeyLength_;
        }
    }
    else
    {
        static assert(false, "Max should be larger or equal to Min");
    }
}
