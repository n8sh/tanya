/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2016.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:belka@caraus.de, Eugene Wissner)
 */  
module tanya.math.mp;

import std.algorithm.comparison;
import std.algorithm.searching;
import std.algorithm.mutation;
import std.experimental.allocator;
import tanya.memory.allocator;
import tanya.memory.types;

struct Integer
{
    private RefCounted!(ubyte[]) rep;
	private bool sign;

	/**
	 * Creates a multiple precision integer.
	 *
	 * Params:
	 * 	value     = Initial value.
	 *	allocator = Allocator.
	 */
	this(in uint value, IAllocator allocator = theAllocator)
	in
	{
		assert(allocator !is null);
	}
	body
	{
		this(allocator);

		immutable size = calculateSizeFromInt(value);
		rep = allocator.makeArray!ubyte(size);
		assignInt(size, value);
	}

	///
	unittest
	{
		auto h = Integer(79);
		assert(h.length == 1);
		assert(h.rep[0] == 79);
	}

	/// Ditto.
	this(in Integer value, IAllocator allocator = theAllocator)
	in
	{
		assert(allocator !is null);
	}
	body
	{
		this(allocator);

		rep = allocator.makeArray!ubyte(value.length);
		value.rep.get.copy(rep.get);
	}

	/// Ditto.
	this(IAllocator allocator)
	{
		this.allocator = allocator;
		rep = RefCounted!(ubyte[])(allocator);
	}

	/*
	 * Figure out the minimum amount of space this value will take
	 * up in bytes (leave at least one byte, though, if the value is 0).
	 */
	pragma(inline, true)
	private ushort calculateSizeFromInt(in ref uint value)
	const pure nothrow @safe @nogc
	{
		ushort size = 4;
		for (uint mask = 0xff000000; mask > 0x000000ff; mask >>= 8)
		{
			if (value & mask)
			{
				break;
			}
			--size;
		}
		return size;
	}
	
	/*
	 * Work backward through the int, masking off each byte
	 * (up to the first 0 byte) and copy it into the internal
	 * representation in big-endian format.
	 */
	pragma(inline, true)
	private void assignInt(in ref ushort size, in ref uint value)
	pure nothrow @safe @nogc
	{
		uint mask = 0x00000000ff, shift;
		for (ushort i = size; i; --i)
		{
			rep[i - 1] = cast(ubyte) ((value & mask) >> shift);
			mask <<= 8;
			shift += 8;
		}

	}

	ref Integer opAssign(in uint value)
	{
		ushort size = calculateSizeFromInt(value);

		checkAllocator();
		allocator.resizeArray(rep.get, size);
		assignInt(size, value);

		return this;
	}

	ref Integer opAssign(in Integer value)
	{
		checkAllocator();
		allocator.resizeArray(rep, value.length);
		value.rep.get.copy(rep.get);

		return this;
	}

	///
	unittest
	{
		auto h = Integer(1019);
		assert(h.length == 2);
		assert(h.rep[0] == 0b00000011 && h.rep[1] == 0b11111011);

		h = 3337;
		assert(h.length == 2);
		assert(h.rep[0] == 0b00001101 && h.rep[1] == 0b00001001);

		h = 688;
		assert(h.length == 2);
		assert(h.rep[0] == 0b00000010 && h.rep[1] == 0b10110000);

		h = 0;
		assert(h.length == 1);
		assert(h.rep[0] == 0);
	}

	/**
	 * Returns: Integer size.
	 */
	@property size_t length() const pure nothrow @safe @nogc
	{
		return rep.get.length;
	}

	/**
	 * Params:
	 * 	h = The second integer.
	 *
	 * Returns: Whether the two integers are equal.
	 */
    bool opEquals(in Integer h) const
    {
        return rep == h.rep;
    }

	///
	unittest
	{
		auto h1 = Integer(1019);

		assert(h1 == Integer(1019));
		assert(h1 != Integer(109));
	}

    /**
	 * Params:
	 * 	h = The second integer.
     *
     * Returns: A positive number if $(D_INLINECODE this > h), a negative
     *          number if $(D_INLINECODE this > h), `0` otherwise.
     */
    int opCmp(in Integer h) const
    {
        if (length > h.length)
        {
            return 1;
        }
        if (length < h.length)
        {
            return -1;
        }

        // Otherwise, keep searching through the representational integers
        // until one is bigger than another - once we've found one, it's
        // safe to stop, since the lower order bytes can't affect the
        // comparison
        int i = 0, j = 0;
        while (i < length && j < h.length)
        {
            if (rep[i] < h.rep[j])
            {
                return -1;
            }
            else if (rep[i] > h.rep[j])
            {
                return 1;
            }
            ++i;
            ++j;
        }
        // if we got all the way to the end without a comparison, the
        // two are equal
        return 0;
    }

    ///
    unittest
    {
		auto h1 = Integer(1019);
		auto h2 = Integer(1019);
		assert(h1 == h2);

		h2 = 3337;
		assert(h1 < h2);

		h2 = 688;
		assert(h1 > h2);
    }

	/**
	 * Assignment operators with another $(D_PSYMBOL Integer).
	 *
	 * Params:
	 * 	h = The second integer.
	 *
	 * Returns: $(D_KEYWORD this).
	 */
	ref Integer opOpAssign(string op)(in Integer h)
		if (op == "+")
	{
		uint sum;
		uint carry = 0;

		checkAllocator();

		// Adding h2 to h1. If h2 is > h1 to begin with, resize h1

		if (h.length > length)
		{
			auto tmp = allocator.makeArray!ubyte(h.length);
			tmp[h.length - length .. $] = rep[0 .. length];
			rep = tmp;
		}

		auto i = length;
		auto j = h.length;

		do
		{
			--i;
			if (j)
			{
				--j;
				sum = rep[i] + h.rep[j] + carry;
			}
			else
			{
				sum = rep[i] + carry;
			}
			carry = sum > 0xff;
			rep[i] = cast(ubyte) sum;
		}
		while (i);

		if (carry)
		{
			// Still overflowed; allocate more space
			auto tmp = allocator.makeArray!ubyte(length + 1);
			tmp[1..$] = rep[0..length];
			tmp[0] = 0x01;
			rep = tmp;
		}
		return this;
	}

	///
	unittest
	{
		auto h1 = Integer(1019);
		
		auto h2 = Integer(3337);
		h1 += h2;
		assert(h1.rep == [0x11, 0x04]);

		h2 = 2_147_483_647;
		h1 += h2;
		assert(h1.rep == [0x80, 0x00, 0x11, 0x03]);

		h1 += h2;
		assert(h1.rep == [0x01, 0x00, 0x00, 0x11, 0x02]);
	}

	/// Ditto.
	ref Integer opOpAssign(string op)(in Integer h)
		if (op == "-")
	{
		auto i = rep.length;
		auto j = h.rep.length;
		uint borrow = 0;

		checkAllocator();

		do
		{
			int difference;
			--i;

			if (j)
			{
				--j;
				difference = rep[i] - h.rep[j] - borrow;
			}
			else
			{
				difference = rep[i] - borrow;
			}
			borrow = difference < 0;
			rep[i] = cast(ubyte) difference;
		}
		while (i);

		if (borrow && i)
		{
			if (!(rep[i - 1])) // Don't borrow i
			{
				throw new Exception("Error, subtraction result is negative\n");
			}
			--rep[i - 1];
		}
		// Go through the representation array and see how many of the
		// left-most bytes are unused. Remove them and resize the array.
		immutable offset = rep.countUntil!(a => a != 0);
		if (offset > 0)
		{
			ubyte[] tmp;
			allocator.resizeArray(tmp, rep.length - offset);
			rep[offset .. $].copy(tmp);
			rep = tmp;
		}
		return this;
	}

	///
	unittest
	{
		auto h1 = Integer(4294967295);
		auto h2 = Integer(4294967295);
		h1 += h2;

		h2 = 2147483647;
		h1 -= h2;
		assert(h1.rep == [0x01, 0x7f, 0xff, 0xff, 0xff]);

		h2 = 4294967294;
		h1 -= h2;
		assert(h1.rep == [0x80, 0x00, 0x00, 0x01]);
	}

	/// Ditto.
	ref Integer opOpAssign(string op)(in size_t n)
		if (op == "<<")
	{
		ubyte carry;
		auto i = rep.length;
		size_t j;
		immutable bit = n % 8;
		immutable delta = 8 - bit;

		checkAllocator();
		if (cast(ubyte) (rep[0] >> delta))
		{
			allocator.resizeArray(rep, i + n / 8 + 1);
			j = i + 1;
		}
		else
		{
			allocator.resizeArray(rep, i + n / 8);
			j = i;
		}
		do
		{
			--i;
			--j;
			immutable oldCarry = carry;
			carry = rep[i] >> delta;
			rep[j] = cast(ubyte) ((rep[i] << bit) | oldCarry);
		}
		while (i);
		if (carry)
		{
			rep[0] = carry;
		}
		return this;
	}

	///
	unittest
	{
		auto h1 = Integer(4294967295);
		h1 <<= 1;
		assert(h1.rep == [0x01, 0xff, 0xff, 0xff, 0xfe]);
	}

	/// Ditto.
	ref Integer opOpAssign(string op)(in size_t n)
		if (op == ">>")
	{
		immutable step = n / 8;

		checkAllocator();
		if (step >= rep.length)
		{
			allocator.resizeArray(rep, 1);
			rep[0] = 0;
			return this;
		}

		size_t i, j;
		ubyte carry;
		immutable bit = n % 8;
		immutable delta = 8 - bit;

		carry = cast(ubyte) (rep[0] << delta);
		rep[0] = (rep[0] >> bit);
		if (rep[0])
		{
			++j;
		}
		for (i = 1; i < rep.length; ++i)
		{
			immutable oldCarry = carry;
			carry = cast(ubyte) (rep[i] << delta);
			rep[j] = (rep[i] >> bit | oldCarry);
			++j;
		}
		rep.length = max(1, rep.length - n / 8 - (i == j ? 0 : 1));

		return this;
	}

	///
	unittest
	{
		auto h1 = Integer(4294967294);
		h1 >>= 10;
		assert(h1.rep == [0x3f, 0xff, 0xff]);

		h1 = 27336704;
		h1 >>= 1;
		assert(h1.rep == [0xd0, 0x90, 0x00]);

		h1 = 4294967294;
		h1 >>= 20;
		assert(h1.rep == [0x0f, 0xff]);

		h1 >>= 0;
		assert(h1.rep == [0x0f, 0xff]);

		h1 >>= 20;
		assert(h1.rep == [0x00]);

		h1 >>= 2;
		assert(h1.rep == [0x00]);

		h1 = 1431655765;
		h1 >>= 16;
		assert(h1.rep == [0x55, 0x55]);

		h1 >>= 16;
		assert(h1.rep == [0x00]);
	}

	/// Ditto.
	ref Integer opOpAssign(string op)(in Integer h)
		if (op == "*")
	{
		ubyte mask;
		auto i = h.rep.length;
		auto temp = Integer(this);

		opAssign(0);
		do
		{
			--i;
			for (mask = 0x01; mask; mask <<= 1)
			{
				if (mask & h.rep[i])
				{
					opOpAssign!"+"(temp);
				}
				temp <<= 1;
			}
		}
		while (i);

		return this;
	}

	///
	unittest
	{
		auto h1 = Integer(123);
		auto h2 = Integer(456);
		h1 *= h2;
		assert(h1.rep == [0xdb, 0x18]); // 56088
	}

	/// Ditto.
	ref Integer opOpAssign(string op)(in Integer h)
		if ((op == "/") || (op == "%"))
	{
		auto divisor = Integer(h);
		// "bit_position" keeps track of which bit, of the quotient,
		// is being set or cleared on the current operation.
		size_t bit_size;

		checkAllocator();

		// First, left-shift divisor until it's >= than the divident
		while (opCmp(divisor) > 0)
		{
			divisor <<= 1;
			++bit_size;
		}
		static if (op == "/")
		{
			auto quotient = allocator.makeArray!ubyte(bit_size / 8 + 1);
		}

		auto bit_position = 8 - (bit_size % 8) - 1;

		do
		{
			if (opCmp(divisor) >= 0)
			{
				opOpAssign!"-"(divisor);
				static if (op == "/")
				{
					quotient[bit_position / 8] |= (0x80 >> (bit_position % 8));
				}
			}

			if (bit_size)
			{
				divisor >>= 1;
			}
			++bit_position;
		}
		while (bit_size--);

		static if (op == "/")
		{
			rep = quotient;
		}
		return this;
	}

	///
	unittest
	{
		auto h1 = Integer(18);
		auto h2 = Integer(4);
		h1 %= h2;
		assert(h1.rep == [0x02]);

		h1 = 8;
		h1 %= h2;
		assert(h1.rep == [0x00]);

		h1 = 7;
		h1 %= h2;
		assert(h1.rep == [0x03]);

		h1 = 56088;
		h2 = 456;
		h1 /= h2;
		assert(h1.rep == [0x7b]); // 123
	}

	/// Ditto.
	ref Integer opOpAssign(string op)(in Integer exp)
		if (op == "^^")
	{
		auto i = exp.rep.length;
		auto tmp1 = Integer(this);
		Integer tmp2;

		opAssign(1);

		do
		{
			--i;
			for (ubyte mask = 0x01; mask; mask <<= 1)
			{
				if (exp.rep[i] & mask)
				{
					opOpAssign!"*"(tmp1);
				}
				// Square tmp1
				tmp2 = tmp1;
				tmp1 *= tmp2;
			}
		}
		while (i);

		return this;
	}

	///
	unittest
	{
		auto h1 = Integer(2);
		auto h2 = Integer(4);

		h1 ^^= h2;
		assert(h1.rep == [0x10]);

		h1 = Integer(2342);
		h1 ^^= h2;
		assert(h1.rep == [0x1b, 0x5c, 0xab, 0x9c, 0x31, 0x10]);
	}

	mixin StructAllocator;
}
