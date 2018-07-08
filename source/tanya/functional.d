/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Functions that manipulate other functions and their argument lists.
 *
 * Copyright: Eugene Wissner 2018.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 * Source: $(LINK2 https://github.com/caraus-ecms/tanya/blob/master/source/tanya/functional.d,
 *                 tanya/functional.d)
 */
module tanya.functional;

import tanya.algorithm.mutation;
import tanya.meta.metafunction;

private template forwardOne(alias arg)
{
    static if (__traits(isRef, arg) || __traits(isOut, arg))
    {
        alias forwardOne = arg;
    }
    else
    {
        @property auto forwardOne()
        {
            return move(arg);
        }
    }
}

/**
 * Forwards its argument list preserving $(D_KEYWORD ref) and $(D_KEYWORD out)
 * storage classes.
 *
 * $(D_PSYMBOL forward) accepts a list of variables or literals. It returns an
 * argument list of the same length that can be for example passed to a
 * function accepting the arguments of this type.
 *
 * Params:
 *  args = Argument list.
 *
 * Returns: $(D_PARAM args) with their original storage classes.
 */
template forward(args...)
{
    static if (args.length == 1)
    {
        alias forward = forwardOne!(args[0]);
    }
    else
    {
        alias forward = Map!(forwardOne, args);
    }
}

///
@nogc nothrow pure @safe unittest
{
    static assert(is(typeof((int i) { int v = forward!i; })));
    static assert(is(typeof((ref int i) { int v = forward!i; })));
    static assert(is(typeof({
        void f(int i, ref int j, out int k)
        {
            f(forward!(i, j, k));
        }
    })));
}