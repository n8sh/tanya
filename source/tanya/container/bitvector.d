/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Single-dimensioned bit array.
 *
 * Copyright: Eugene Wissner 2016-2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.container.bitvector;

import tanya.memory;

/**
 * Single-dimensioned bit array.
 */
struct BitVector
{
    private size_t length_;
    private ubyte* data;
    private size_t capacity_;

    pure nothrow @safe @nogc invariant
    {
        assert(this.capacity_ <= size_t.max / 8);
        assert(this.capacity_ * 8 - this.length_ <= 8);
        assert(this.capacity_ == 0 || this.data !is null);
    }

    /**
     * Params:
     *  array     = Array should be manipulated on.
     *  allocator = Allocator.
     */
    this(ubyte[] array, shared Allocator allocator = defaultAllocator)
    pure nothrow @trusted @nogc
    in
    {
        assert(array.length <= size_t.max / 8);
    }
    body
    {
        this(allocator);
        this.data = array.ptr;
        this.capacity_ = array.length;
        this.length_ = array.length * 8;
    }

    ///
    unittest
    {
        ubyte[5] array1 = [234, 3, 252, 10, 18];
        ubyte[3] array2 = [65, 13, 173];
        auto bits = BitVector(array1);

        assert(bits.get() is array1);
        assert(bits.get() !is array2);

        bits = BitVector(array2);
        assert(bits.get() is array2);
    }

    /// Ditto.
    this(shared Allocator allocator) pure nothrow @safe @nogc
    in
    {
        assert(allocator !is null);
    }
    body
    {
        this.allocator_ = allocator;
    }

    /**
     * Returns: Capacity in bits.
     */
    @property size_t capacity() const pure nothrow @safe @nogc
    {
        return this.capacity_ * 8;
    }

    /**
     * Returns: Number of bits in the vector.
     */
    @property size_t length() const pure nothrow @safe @nogc
    {
        return this.length_;
    }

    /// Ditto.
    size_t opDollar() const pure nothrow @safe @nogc
    {
        return length;
    }

    ///
    unittest
    {
        // [01000001, 00001101, 10101101]
        ubyte[3] arr = [65, 13, 173];
        auto bits = BitVector(arr);

        assert(bits.length == 24);
    }

    /**
     * Params:
     *  bit = Bit position.
     *
     * Returns: $(D_KEYWORD true) if the bit on position $(D_PARAM bit) is set,
     *          $(D_KEYWORD false) if not set.
     */
    inout(bool) opIndex(size_t bit) inout const pure nothrow @trusted @nogc
    in
    {
        assert(bit <= length);
    }
    body
    {
        return (data[bit / 8] & (0x80 >> (bit % 8))) != 0;
    }

    ///
    unittest
    {
        // [01000001, 00001101, 10101101]
        ubyte[3] arr = [65, 13, 173];
        auto bits = BitVector(arr);

        assert(!bits[0]);
        assert(bits[1]);
        assert(bits[7]);
        assert(!bits[8]);
        assert(!bits[11]);
        assert(bits[12]);
        assert(bits[20]);
        assert(bits[23]);
    }

    /**
     * Returns: Underlying array.
     */
    ubyte[] get() pure nothrow @trusted @nogc
    {
        return this.data[0 .. this.capacity_];
    }

    /// Ditto.
    const(ubyte[]) get() const pure nothrow @trusted @nogc
    {
        return this.data[0 .. this.capacity_];
    }

    ///
    unittest
    {
        // [01000001, 00001101, 10101101]
        ubyte[3] arr = [65, 13, 173];
        auto bits = BitVector(arr);

        assert(bits.get() is arr);
    }

    /**
     * Params:
     *  value = $(D_KEYWORD true) if the bit should be set,
     *          $(D_KEYWORD false) if cleared.
     *  bit   = Bit position.
     *
     * Returns: $(D_PSYMBOL this).
     */
    bool opIndexAssign(bool value, size_t bit) pure nothrow @trusted @nogc
    in
    {
        assert(bit <= length);
    }
    body
    {
        if (value)
        {
            data[bit / 8] |= (0x80 >> (bit % 8));
        }
        else
        {
            data[bit / 8] &= ~(0x80 >> (bit % 8));
        }
        return value;
    }

    ///
    unittest
    {
        // [01000001, 00001101, 10101101]
        ubyte[3] arr = [65, 13, 173];
        auto bits = BitVector(arr);

        bits[5] = bits[6] = true;
        assert(bits.get()[0] == 71);

        bits[14] = true;
        bits[15] = false;
        assert(bits.get()[1] == 14);

        bits[16] = bits[23] = false;
        assert(bits.get()[2] == 44);
    }

    /**
     * Copies bits from $(D_PARAM vector) into this $(D_PSYMBOL BitVector).
     *
     * The array that should be assigned, can be smaller (but not larger) than
     * the underlying array of this $(D_PSYMBOL BitVector), leading zeros will
     * be added in this case to the left.
     *
     * Params:
     *  vector = $(D_KEYWORD ubyte[]) array not larger than
     *           `$(D_PSYMBOL length) / 8`.
     *
     * Returns: $(D_KEYWORD this).
     */
    BitVector opAssign(ubyte[] vector) pure nothrow @trusted @nogc
    in
    {
        assert(vector.length <= this.capacity_);
    }
    body
    {
        const delta = this.capacity_ - vector.length;
        if (delta > 0)
        {
            this.data[0 .. delta] = 0;
        }
        this.data[delta .. this.capacity_] = vector[0 .. $];
        return this;
    }

    ///
    unittest
    {
        ubyte[5] array1 = [234, 3, 252, 10, 18];
        ubyte[3] array2 = [65, 13, 173];
        auto bits = BitVector(array1);

        bits = array2;
        assert(bits.get()[0] == 0);
        assert(bits.get()[1] == 0);
        assert(bits.get()[2] == 65);
        assert(bits.get()[3] == 13);
        assert(bits.get()[4] == 173);

        bits = array2[0 .. 2];
        assert(bits.get()[0] == 0);
        assert(bits.get()[1] == 0);
        assert(bits.get()[2] == 0);
        assert(bits.get()[3] == 65);
        assert(bits.get()[4] == 13);
    }

    /**
     * Support for bitwise operations.
     *
     * Params:
     *  that = Another bit vector.
     *
     * Returns: $(D_KEYWORD this).
     */
    BitVector opOpAssign(string op)(BitVector that) pure nothrow @safe @nogc
        if ((op == "^") || (op == "|") || (op == "&"))
    {
        return opOpAssign(op)(that.data[0 .. that.capacity_]);
    }

    /// Ditto.
    BitVector opOpAssign(string op)(ubyte[] that) pure nothrow @trusted @nogc
        if ((op == "^") || (op == "|") || (op == "&"))
    in
    {
        assert(that.length <= this.capacity_);
    }
    body
    {
        for (int i = cast(int) this.capacity_ - 1; i >= 0; --i)
        {
            mixin("data[i] " ~  op ~ "= " ~ "that[i];");
        }
        const delta = this.capacity_ - that.length;
        if (delta)
        {
            static if (op == "&")
            {
                data[0 .. delta] = 0;
            }
        }
        return this;
    }

    ///
    unittest
    {
        // [01000001, 00001101, 10101101]
        ubyte[3] array1 = [65, 13, 173];
        ubyte[3] array2 = [0b01010010, 0b10111110, 0b10111110];
        auto bits = BitVector(array1);

        bits |= array2;
        assert(bits.get()[0] == 0b01010011);
        assert(bits.get()[1] == 0b10111111);
        assert(bits.get()[2] == 0b10111111);

        bits &= array2;
        assert(bits.get()[0] == array2[0]);
        assert(bits.get()[1] == array2[1]);
        assert(bits.get()[2] == array2[2]);

        bits ^= array2;
        assert(bits.get()[0] == 0);
        assert(bits.get()[1] == 0);
        assert(bits.get()[2] == 0);
    }

    /**
     * Support for shift operations.
     *
     * Params:
     *  n = Number of bits.
     *
     * Returns: $(D_KEYWORD this).
     */
    BitVector opOpAssign(string op)(in size_t n) pure nothrow @trusted @nogc
        if ((op == "<<") || (op == ">>"))
    {
        if (n >= length)
        {
            data[0 .. this.capacity_] = 0;
        }
        else if (n != 0)
        {
            const bit = n % 8, step = n / 8;
            const delta = 8 - bit;
            size_t i, j;

            static if (op == "<<")
            {
                for (j = step; j < this.capacity_ - 1; ++i)
                {
                    this.data[i] = cast(ubyte) ((this. data[j] << bit)
                                 | this.data[++j] >> delta);
                }
                this.data[i] = cast(ubyte) (this.data[j] << bit);
                this.data[this.capacity_ - step .. this.capacity_] = 0;
            }
            else static if (op == ">>")
            {
                for (i = this.capacity_ - 1, j = i - step; j > 0; --i)
                {
                    this.data[i] = cast(ubyte) ((this.data[j] >> bit)
                                 | this.data[--j] << delta);
                }
                this.data[i] = cast(ubyte) (this.data[j] >> bit);
                this.data[0 .. step] = 0;
            }
        }
        return this;
    }

    private nothrow @safe @nogc unittest
    {
        ubyte[4] arr = [0b10111110, 0b11110010, 0b01010010, 0b01010011];
        auto bits = BitVector(arr);

        bits <<= 0;
        assert(bits.get()[0] == 0b10111110 && bits.get()[1] == 0b11110010
            && bits.get()[2] == 0b01010010 && bits.get()[3] == 0b01010011);

        bits <<= 2;
        assert(bits.get()[0] == 0b11111011 && bits.get()[1] == 0b11001001
            && bits.get()[2] == 0b01001001 && bits.get()[3] == 0b01001100);

        bits <<= 4;
        assert(bits.get()[0] == 0b10111100 && bits.get()[1] == 0b10010100
            && bits.get()[2] == 0b10010100 && bits.get()[3] == 0b11000000);

        bits <<= 8;
        assert(bits.get()[0] == 0b10010100 && bits.get()[1] == 0b10010100
            && bits.get()[2] == 0b11000000 && bits.get()[3] == 0b00000000);

        bits <<= 7;
        assert(bits.get()[0] == 0b01001010 && bits.get()[1] == 0b01100000
            && bits.get()[2] == 0b00000000 && bits.get()[3] == 0b00000000);

        bits <<= 25;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00000000 && bits.get()[3] == 0b00000000);

        arr = [0b00110011, 0b11001100, 0b11111111, 0b01010101];
        bits <<= 24;
        assert(bits.get()[0] == 0b01010101 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00000000 && bits.get()[3] == 0b00000000);

        arr[1] = 0b11001100;
        arr[2] = 0b11111111;
        arr[3] = 0b01010101;
        bits <<= 12;
        assert(bits.get()[0] == 0b11001111 && bits.get()[1] == 0b11110101
            && bits.get()[2] == 0b01010000 && bits.get()[3] == 0b00000000);

        bits <<= 100;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00000000 && bits.get()[3] == 0b00000000);

        arr = [0b10111110, 0b11110010, 0b01010010, 0b01010011];
        bits >>= 0;
        assert(bits.get()[0] == 0b10111110 && bits.get()[1] == 0b11110010
            && bits.get()[2] == 0b01010010 && bits.get()[3] == 0b01010011);

        bits >>= 2;
        assert(bits.get()[0] == 0b00101111 && bits.get()[1] == 0b10111100
            && bits.get()[2] == 0b10010100 && bits.get()[3] == 0b10010100);

        bits >>= 4;
        assert(bits.get()[0] == 0b00000010 && bits.get()[1] == 0b11111011
            && bits.get()[2] == 0b11001001 && bits.get()[3] == 0b01001001);

        bits >>= 8;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000010
            && bits.get()[2] == 0b11111011 && bits.get()[3] == 0b11001001);

        bits >>= 7;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00000101 && bits.get()[3] == 0b11110111);

        bits >>= 25;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00000000 && bits.get()[3] == 0b00000000);

        arr = [0b00110011, 0b11001100, 0b11111111, 0b01010101];
        bits >>= 24;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00000000 && bits.get()[3] == 0b00110011);

        arr[1] = 0b11001100;
        arr[2] = 0b11111111;
        arr[3] = 0b01010101;
        bits >>= 12;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00001100 && bits.get()[3] == 0b11001111);

        bits >>= 100;
        assert(bits.get()[0] == 0b00000000 && bits.get()[1] == 0b00000000
            && bits.get()[2] == 0b00000000 && bits.get()[3] == 0b00000000);
    }

    /**
     * Negates all bits.
     *
     * Returns: $(D_KEYWORD this).
     */
    BitVector opUnary(string op)() @trusted
        if (op == "~")
    {
        foreach (ref b; this.data[0 .. this.capacity_])
        {
            b = ~b;
        }
        return this;
    }

    ///
    unittest
    {
        // [01000001, 00001101, 10101101]
        ubyte[3] arr = [65, 13, 173];
        auto bits = BitVector(arr);

        ~bits;
        assert(bits.get()[0] == 0b10111110);
        assert(bits.get()[1] == 0b11110010);
        assert(bits.get()[2] == 0b01010010);
    }

    /**
     * Iterates through all bits.
     *
     * Params:
     *  dg = $(D_KEYWORD foreach) delegate.
     *
     * Returns: By $(D_PARAM dg) returned value.
     */
    int opApply(int delegate(size_t, bool) dg) @trusted
    {
        int result;
        foreach (i, ref v; this.data[0 .. this.capacity_])
        {
            foreach (c; 0 .. 8)
            {
                result = dg(i * 8 + c, (v & (0x80 >> c)) != 0);
                if (result)
                {
                    return result;
                }
            }
        }
        return result;
    }

    /// Ditto.
    int opApply(int delegate(bool) dg) @trusted
    {
        int result;
        foreach (ref v; this.data[0 .. this.capacity_])
        {
            foreach (c; 0 .. 8)
            {
                result = dg((v & (0x80 >> c)) != 0);
                if (result)
                {
                    return result;
                }
            }
        }
        return result;
    }

    ///
    unittest
    {
        ubyte[2] arr = [0b01000001, 0b00001101];
        auto bits = BitVector(arr);
        size_t c;

        foreach (i, v; bits)
        {
            assert(i == c);
            if (i == 1 || i == 7 || i == 15 || i == 13 || i == 12)
            {
                assert(v);
            }
            else
            {
                assert(!v);
            }
            ++c;
        }
        assert(c == 16);
    }

    mixin DefaultAllocator;
}
