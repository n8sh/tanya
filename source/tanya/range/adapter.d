/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Range adapters.
 *
 * A range adapter wraps another range and modifies the way, how the original
 * range is iterated, or the order in which its elements are accessed.
 *
 * All adapters are lazy algorithms, they request the next element of the
 * adapted range on demand.
 *
 * Copyright: Eugene Wissner 2018.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 * Source: $(LINK2 https://github.com/caraus-ecms/tanya/blob/master/source/tanya/range/adapter.d,
 *                 tanya/range/adapter.d)
 */
deprecated("Use tanya.algorithm.iteration instead")
module tanya.range.adapter;

import tanya.algorithm.mutation;
import tanya.math;
import tanya.range.primitive;

private mixin template Take(R, bool exactly)
{
    private R source;
    size_t length_;

    @disable this();

    private this(R source, size_t length)
    {
        this.source = source;
        static if (!exactly && hasLength!R)
        {
            this.length_ = min(source.length, length);
        }
        else
        {
            this.length_ = length;
        }
    }

    @property auto ref front()
    in
    {
        assert(!empty);
    }
    do
    {
        return this.source.front;
    }

    void popFront()
    in
    {
        assert(!empty);
    }
    do
    {
        this.source.popFront();
        --this.length_;
    }

    @property bool empty()
    {
        static if (exactly || isInfinite!R)
        {
            return length == 0;
        }
        else
        {
            return length == 0 || this.source.empty;
        }
    }

    @property size_t length()
    {
        return this.length_;
    }

    static if (hasAssignableElements!R)
    {
        @property void front(ref ElementType!R value)
        in
        {
            assert(!empty);
        }
        do
        {
            this.source.front = value;
        }

        @property void front(ElementType!R value)
        in
        {
            assert(!empty);
        }
        do
        {
            this.source.front = move(value);
        }
    }

    static if (isForwardRange!R)
    {
        typeof(this) save()
        {
            return typeof(this)(this.source.save(), length);
        }
    }
    static if (isRandomAccessRange!R)
    {
        @property auto ref back()
        in
        {
            assert(!empty);
        }
        do
        {
            return this.source[this.length - 1];
        }

        void popBack()
        in
        {
            assert(!empty);
        }
        do
        {
            --this.length_;
        }

        auto ref opIndex(size_t i)
        in
        {
            assert(i < length);
        }
        do
        {
            return this.source[i];
        }

        static if (hasAssignableElements!R)
        {
            @property void back(ref ElementType!R value)
            in
            {
                assert(!empty);
            }
            do
            {
                this.source[length - 1] = value;
            }

            @property void back(ElementType!R value)
            in
            {
                assert(!empty);
            }
            do
            {
                this.source[length - 1] = move(value);
            }

            void opIndexAssign(ref ElementType!R value, size_t i)
            in
            {
                assert(i < length);
            }
            do
            {
                this.source[i] = value;
            }

            void opIndexAssign(ElementType!R value, size_t i)
            in
            {
                assert(i < length);
            }
            do
            {
                this.source[i] = move(value);
            }
        }
    }
    static if (hasSlicing!R)
    {
        auto opSlice(size_t i, size_t j)
        in
        {
            assert(i <= j);
            assert(j <= length);
        }
        do
        {
            return take(this.source[i .. j], length);
        }
    }
}

/**
 * Takes $(D_PARAM n) elements from $(D_PARAM range).
 *
 * If $(D_PARAM range) doesn't have $(D_PARAM n) elements, the resulting range
 * spans all elements of $(D_PARAM range).
 *
 * $(D_PSYMBOL take) is particulary useful with infinite ranges. You can take
 ` $(B n) elements from such range and pass the result to an algorithm which
 * expects a finit range.
 *
 * Params:
 *  R     = Type of the adapted range.
 *  range = The range to take the elements from.
 *  n     = The number of elements to take.
 *
 * Returns: A range containing maximum $(D_PARAM n) first elements of
 *          $(D_PARAM range).
 *
 * See_Also: $(D_PSYMBOL takeExactly).
 */
auto take(R)(R range, size_t n)
if (isInputRange!R)
{
    struct Take
    {
        mixin .Take!(R, false);
    }
    return Take(range, n);
}

/**
 * Takes exactly $(D_PARAM n) elements from $(D_PARAM range).
 *
 * $(D_PARAM range) must have at least $(D_PARAM n) elements.
 *
 * $(D_PSYMBOL takeExactly) is particulary useful with infinite ranges. You can
 ` take $(B n) elements from such range and pass the result to an algorithm
 * which expects a finit range.
 *
 * Params:
 *  R     = Type of the adapted range.
 *  range = The range to take the elements from.
 *  n     = The number of elements to take.
 *
 * Returns: A range containing $(D_PARAM n) first elements of $(D_PARAM range).
 *
 * See_Also: $(D_PSYMBOL take).
 */
auto takeExactly(R)(R range, size_t n)
if (isInputRange!R)
{
    struct TakeExactly
    {
        mixin Take!(R, true);
    }
    return TakeExactly(range, n);
}
