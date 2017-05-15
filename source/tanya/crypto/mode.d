/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Block cipher modes of operation.
 *
 * Copyright: Eugene Wissner 2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.crypto.mode;

import std.algorithm.mutation;
import std.typecons;
import tanya.container.vector;
import tanya.crypto.symmetric;
import tanya.memory;

/**
 * Supported padding mode.
 *
 * See_Also:
 *  $(D_PSYMBOL pad)
 */
enum PaddingMode
{
    zero,
    pkcs7,
    ansiX923,
}

/**
 * Params:
 *  input     = Sequence that should be padded.
 *  mode      = Padding mode.
 *  blockSize = Block size.
 *  allocator = Allocator was used to allocate $(D_PARAM input).
 *
 * Returns: The function modifies the initial array and returns it.
 *
 * See_Also:
 *  $(D_PSYMBOL PaddingMode)
 */
ubyte[] pad(ref ubyte[] input,
            in PaddingMode mode,
            in ushort blockSize,
            shared Allocator allocator = defaultAllocator)
in
{
    assert(blockSize > 0 && blockSize <= 256);
    assert(blockSize % 64 == 0);
    assert(input.length > 0);
}
body
{
    immutable rest = cast(ubyte) input.length % blockSize;
    immutable size_t lastBlock = input.length - (rest > 0 ? rest : blockSize);
    immutable needed = cast(ubyte) (rest > 0 ? blockSize - rest : 0);

    final switch (mode) with (PaddingMode)
    {
        case zero:
            input = allocator.resize(input, input.length + needed);
            input[input.length - needed .. $].fill(cast(ubyte) 0);
            break;
        case pkcs7:
            if (needed)
            {
                input = allocator.resize(input, input.length + needed);
                input[input.length - needed .. $].fill(needed);
            }
            else
            {
                input = allocator.resize(input, input.length + blockSize);
                input[$ - blockSize .. $].fill(ubyte.init);
            }
            break;
        case ansiX923:
            const delta = needed ? needed : blockSize;
            input = allocator.resize(input, input.length + delta);
            input[$ - delta .. $ - 1].fill(ubyte.init);
            input[$ - 1] = needed;
            break;
    }

    return input;
}

///
unittest
{
    { // Zeros
        auto input = defaultAllocator.resize!ubyte(null, 50);

        pad(input, PaddingMode.zero, 64);
        assert(input.length == 64);

        pad(input, PaddingMode.zero, 64);
        assert(input.length == 64);
        assert(input[63] == 0);

        defaultAllocator.dispose(input);
    }
    { // PKCS#7
        auto input = defaultAllocator.resize!ubyte(null, 50);
        for (ubyte i; i < 50; ++i)
        {
            input[i] = i < 40 ? i : 0;
        }

        pad(input, PaddingMode.pkcs7, 64);
        assert(input.length == 64);
        for (ubyte i; i < 64; ++i)
        {
            if (i >= 40 && i < 50)
            {
                assert(input[i] == 0);
            }
            else if (i >= 50)
            {
                assert(input[i] == 14);
            }
            else
            {
                assert(input[i] == i);
            }
        }

        pad(input, PaddingMode.pkcs7, 64);
        assert(input.length == 128);
        for (ubyte i; i < 128; ++i)
        {
            if (i >= 64 || (i >= 40 && i < 50))
            {
                assert(input[i] == 0);
            }
            else if (i >= 50 && i < 64)
            {
                assert(input[i] == 14);
            }
            else
            {
                assert(input[i] == i);
            }
        }

        defaultAllocator.dispose(input);
    }
    { // ANSI X.923
        auto input = defaultAllocator.resize!ubyte(null, 50);
        for (ubyte i; i < 50; ++i)
        {
            input[i] = i < 40 ? i : 0;
        }

        pad(input, PaddingMode.ansiX923, 64);
        assert(input.length == 64);
        for (ubyte i; i < 64; ++i)
        {
            if (i < 40)
            {
                assert(input[i] == i);
            }
            else if (i == 63)
            {
                assert(input[i] == 14);
            }
            else
            {
                assert(input[i] == 0);
            }
        }

        pad(input, PaddingMode.pkcs7, 64);
        assert(input.length == 128);
        for (ubyte i = 0; i < 128; ++i)
        {
            if (i < 40)
            {
                assert(input[i] == i);
            }
            else if (i == 63)
            {
                assert(input[i] == 14);
            }
            else
            {
                assert(input[i] == 0);
            }
        }

        defaultAllocator.dispose(input);
    }
}

/**
 * Params:
 *  input     = Sequence that should be padded.
 *  mode      = Padding mode.
 *  blockSize = Block size.
 *  allocator = Allocator was used to allocate $(D_PARAM input).
 *
 * Returns: The function modifies the initial array and returns it.
 *
 * See_Also:
 *  $(D_PSYMBOL pad)
 */
ref ubyte[] unpad(ref ubyte[] input,
                  in PaddingMode mode,
                  in ushort blockSize,
                  shared Allocator allocator = defaultAllocator)
in
{
    assert(input.length != 0);
    assert(input.length % 64 == 0);
}
body
{
    final switch (mode) with (PaddingMode)
    {
        case zero:
            break;
        case pkcs7:
        case ansiX923:
            immutable last = input[$ - 1];

            input = allocator.resize(input, input.length - (last ? last : blockSize));
            break;
    }

    return input;
}

///
unittest
{
    { // Zeros
        auto input = defaultAllocator.resize!ubyte(null, 50);
        auto inputDup = defaultAllocator.resize!ubyte(null, 50);
        input.fill(ubyte.init);
        inputDup.fill(ubyte.init);

        pad(input, PaddingMode.zero, 64);
        pad(inputDup, PaddingMode.zero, 64);

        unpad(input, PaddingMode.zero, 64);
        assert(input == inputDup);

        defaultAllocator.dispose(input);
        defaultAllocator.dispose(inputDup);

    }
    { // PKCS#7
        auto input = defaultAllocator.resize!ubyte(null, 50);
        auto inputDup = defaultAllocator.resize!ubyte(null, 50);
        for (ubyte i; i < 40; ++i)
        {
            input[i] = i;
            inputDup[i] = i;
        }

        pad(input, PaddingMode.pkcs7, 64);
        unpad(input, PaddingMode.pkcs7, 64);
        assert(input == inputDup);

        defaultAllocator.dispose(input);
        defaultAllocator.dispose(inputDup);
    }
    { // ANSI X.923
        auto input = defaultAllocator.resize!ubyte(null, 50);
        auto inputDup = defaultAllocator.resize!ubyte(null, 50);

        for (ubyte i; i < 40; ++i)
        {
            input[i] = i;
            inputDup[i] = i;
        }

        pad(input, PaddingMode.pkcs7, 64);
        unpad(input, PaddingMode.pkcs7, 64);
        assert(input == inputDup);

        defaultAllocator.dispose(input);
        defaultAllocator.dispose(inputDup);
    }
}

/**
 * Block cipher mode of operation.
 */
interface CipherMode
{
    // DMD bug 15984: https://issues.dlang.org/show_bug.cgi?id=15984
    static if (__VERSION__ > 2070)
    {
        /**
         * (Re)starts processing the message.
         *
         * Params:
         *  direction = Encryption or decryption.
         *  iv        = Initialization vector.
         *
         * Precondition: $(D_INLINECODE this.cipher !is null
         *                           && iv.length = this.cipher.blockLength).
         */
        void start(Direction direction, ref const Vector!ubyte iv);
    }
    else
    {
        void start(Direction direction, ref const Vector!ubyte iv)
        in
        {
            assert(this.cipher !is null);
            assert(iv.length == this.cipher.blockLength);
        }
    }

    /// Ditto.
    void start(Direction direction);

    /**
     * Finish processing the message.
     */
    void finish();

    /**
     * Returns: Encryption or decryption.
     */
    @property Nullable!Direction direction() const;

    /**
     * Processes a message.
     *
     * Params:
     *  input  = Input.
     *  output = Output.
     *
     * Precondition: $(D_INLINECODE !direction.isNull && 
     *                              input.length % cipher.blockLength == 0 &&
     *                              input.length == output.length).
     */
    void process(ref const Vector!ubyte input, ref Vector!ubyte output)
    in
    {
        assert(!direction.isNull);
        assert(input.length % cipher.blockLength == 0);
        assert(input.length == output.length);
    }

    /**
     * Returns: Initialization vector.
     */
    @property ref const(Vector!ubyte) iv() const;

    /**
     * Resets the key.
     *
     * Params:
     *  key = Key.
     *
     * Precondition: $(D_INLINECODE this.cipher !is null
     *                           && key.length = this.cipher.keyLength).
     */
    @property void key(ref const Vector!ubyte key)
    in
    {
        assert(this.cipher !is null);
        assert(this.cipher.keyLength == key.length);
    }

    /**
     * Returns: Used cipher.
     */
    @property const(BlockCipher) cipher() const;
}

/**
 * Cipher Block Chaining mode.
 */
class CBC : CipherMode
{
    private BlockCipher cipher_;
    private Nullable!Direction direction_;
    private Vector!ubyte iv_;

    invariant
    {
        assert(this.cipher_ !is null);
    }

    /**
     * Returns: Encryption or decryption.
     */
    @property Nullable!Direction direction() const
    {
        return this.direction_;
    }

    /**
     * Returns: Used cipher.
     */
    @property const(BlockCipher) cipher() const
    {
        return this.cipher_;
    }

    /**
     * Initializes the cipher mode with $(D_PARAM cipher).
     *
     * Params:
     *  cipher = The block cipher should be used.
     */
    this(BlockCipher cipher)
    in
    {
        assert(cipher !is null);
    }
    body
    {
        this.cipher_ = cipher;
    }

    /**
     * (Re)starts processing the message.
     *
     * Params:
     *  direction = Encryption or decryption.
     *  iv        = Initialization vector.
     *
     * Precondition: $(D_INLINECODE this.cipher !is null
     *                           && iv.length = this.cipher.blockLength).
     */
    void start(Direction direction, ref const Vector!ubyte iv)
    in
    {
        assert(iv.length == this.cipher.blockLength);
    }
    body
    {
        this.direction_ = direction;
        this.iv_ = iv;
    }

    /// Ditto.
    void start(Direction direction)
    {
        this.direction_ = direction;
        this.iv_.length = this.cipher.blockLength;
        this.iv_[].fill(ubyte.init);
    }

    /**
     * Finish processing the message.
     */
    void finish()
    {
        this.direction_.nullify();
    }

    /**
     * Processes a message.
     *
     * Params:
     *  input  = Input.
     *  output = Output.
     *
     * Precondition: $(D_INLINECODE !direction.isNull && 
     *                              input.length % cipher.blockLength == 0 &&
     *                              input.length == output.length).
     */
    void process(ref const Vector!ubyte input, ref Vector!ubyte output)
    in
    {
        assert(!this.direction.isNull);
        assert(input.length % cipher.blockLength == 0);
        assert(input.length == output.length);
    }
    body
    {
        size_t pos;
        auto inBlock = Vector!ubyte(this.cipher.blockLength);
        auto outBlock = Vector!ubyte(this.cipher.blockLength);

        final switch (this.direction) with (Direction)
        {
            case encryption:
                while (pos < input.length)
                {
                    inBlock = input[pos .. pos + this.cipher.blockLength];
                    xor(inBlock.get(), this.iv_.get());

                    this.cipher_.encrypt(inBlock, outBlock);

                    output[pos .. pos + this.cipher.blockLength] = outBlock[];
                    this.iv_ = outBlock;

                    pos += this.cipher.blockLength;
                }
                break;
            case decryption:
                while (pos < input.length)
                {
                    inBlock = input[pos .. pos + this.cipher.blockLength];
                    this.cipher_.decrypt(inBlock, outBlock);

                    xor(outBlock.get(), this.iv_.get());
                    output[pos .. pos + this.cipher.blockLength] = outBlock[];

                    this.iv_ = inBlock;

                    pos += this.cipher.blockLength;
                }
                break;
        }
    }

    /**
     * Returns: Initialization vector.
     */
    @property ref const(Vector!ubyte) iv() const
    {
        return iv_;
    }

    /**
     * Resets the key.
     *
     * Params:
     *  key = Key.
     *
     * Precondition: $(D_INLINECODE this.cipher !is null
     *                           && key.length = this.cipher.keyLength).
     */
    @property void key(ref const Vector!ubyte key)
    in
    {
        assert(this.cipher !is null);
        assert(this.cipher.keyLength == key.length);
    }
    body
    {
        this.cipher_.key = key;
    }
}
