/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Copyright: Eugene Wissner 2016-2017.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 */
module tanya.memory;

import core.exception;
public import std.experimental.allocator : make;
import std.traits;
public import tanya.memory.allocator;

/**
 * The mixin generates common methods for classes and structs using
 * allocators. It provides a protected member, constructor and a read-only property,
 * that checks if an allocator was already set and sets it to the default
 * one, if not (useful for structs which don't have a default constructor).
 */
mixin template DefaultAllocator()
{
    /// Allocator.
    protected shared Allocator allocator_;

    /**
     * Params:
     *  allocator = The allocator should be used.
     *
     * Precondition: $(D_INLINECODE allocator_ !is null)
     */
    this(shared Allocator allocator)
    in
    {
        assert(allocator !is null);
    }
    body
    {
        this.allocator_ = allocator;
    }

    /**
     * This property checks if the allocator was set in the constructor
     * and sets it to the default one, if not.
     *
     * Returns: Used allocator.
     *
     * Postcondition: $(D_INLINECODE allocator !is null)
     */
    protected @property shared(Allocator) allocator() nothrow @safe @nogc
    out (allocator)
    {
        assert(allocator !is null);
    }
    body
    {
        if (allocator_ is null)
        {
            allocator_ = defaultAllocator;
        }
        return allocator_;
    }

    /// Ditto.
    @property shared(Allocator) allocator() const nothrow @trusted @nogc
    out (allocator)
    {
        assert(allocator !is null);
    }
    body
    {
        if (allocator_ is null)
        {
            return defaultAllocator;
        }
        return cast(shared Allocator) allocator_;
    }
}

// From druntime
private extern (C) void _d_monitordelete(Object h, bool det) nothrow @nogc;

shared Allocator allocator;

shared static this() nothrow @trusted @nogc
{
    import tanya.memory.mallocator;
    allocator = Mallocator.instance;
}

@property ref shared(Allocator) defaultAllocator() nothrow @safe @nogc
out (allocator)
{
    assert(allocator !is null);
}
body
{
    return allocator;
}

@property void defaultAllocator(shared(Allocator) allocator) nothrow @safe @nogc
in
{
    assert(allocator !is null);
}
body
{
    .allocator = allocator;
}

/**
 * Returns the size in bytes of the state that needs to be allocated to hold an
 * object of type $(D_PARAM T).
 *
 * Params:
 *  T = Object type.
 */
template stateSize(T)
{
    static if (is(T == class) || is(T == interface))
    {
        enum stateSize = __traits(classInstanceSize, T);
    }
    else
    {
        enum stateSize = T.sizeof;
    }
}

/**
 * Params:
 *  size      = Raw size.
 *  alignment = Alignment.
 *
 * Returns: Aligned size.
 */
size_t alignedSize(const size_t size, const size_t alignment = 8)
pure nothrow @safe @nogc
{
    return (size - 1) / alignment * alignment + alignment;
}

/**
 * Internal function used to create, resize or destroy a dynamic array. It
 * may throw $(D_PSYMBOL OutOfMemoryError). The new
 * allocated part of the array isn't initialized. This function can be trusted
 * only in the data structures that can ensure that the array is
 * allocated/rellocated/deallocated with the same allocator.
 *
 * Params:
 *  T         = Element type of the array being created.
 *  allocator = The allocator used for getting memory.
 *  array     = A reference to the array being changed.
 *  length    = New array length.
 *
 * Returns: $(D_PARAM array).
 */
package(tanya) T[] resize(T)(shared Allocator allocator,
                             auto ref T[] array,
                             const size_t length) @trusted
{
    if (length == 0)
    {
        if (allocator.deallocate(array))
        {
            return null;
        }
        else
        {
            onOutOfMemoryErrorNoGC();
        }
    }

    void[] buf = array;
    if (!allocator.reallocate(buf, length * T.sizeof))
    {
        onOutOfMemoryErrorNoGC();
    }
    // Casting from void[] is unsafe, but we know we cast to the original type.
    array = cast(T[]) buf;

    return array;
}

private unittest
{
    int[] p;

    p = defaultAllocator.resize(p, 20);
    assert(p.length == 20);

    p = defaultAllocator.resize(p, 30);
    assert(p.length == 30);

    p = defaultAllocator.resize(p, 10);
    assert(p.length == 10);

    p = defaultAllocator.resize(p, 0);
    assert(p is null);
}

/**
 * Destroys and deallocates $(D_PARAM p) of type $(D_PARAM T).
 * It is assumed the respective entities had been allocated with the same
 * allocator.
 *
 * Params:
 *  T         = Type of $(D_PARAM p).
 *  allocator = Allocator the $(D_PARAM p) was allocated with.
 *  p         = Object or array to be destroyed.
 */
void dispose(T)(shared Allocator allocator, auto ref T* p)
{
    static if (hasElaborateDestructor!T)
    {
        destroy(*p);
    }
    () @trusted { allocator.deallocate((cast(void*) p)[0 .. T.sizeof]); }();
    p = null;
}

/// Ditto.
void dispose(T)(shared Allocator allocator, auto ref T p)
    if (is(T == class) || is(T == interface))
{
    if (p is null)
    {
        return;
    }
    static if (is(T == interface))
    {
        version(Windows)
        {
            import core.sys.windows.unknwn : IUnknown;
            static assert(!is(T: IUnknown), "COM interfaces can't be destroyed in "
                                         ~ __PRETTY_FUNCTION__);
        }
        auto ob = cast(Object) p;
    }
    else
    {
        alias ob = p;
    }
    auto ptr = cast(void *) ob;

    auto support = ptr[0 .. typeid(ob).initializer.length];
    scope (success)
    {
        () @trusted { allocator.deallocate(support); }();
        p = null;
    }

    auto ppv = cast(void**) ptr;
    if (!*ppv)
    {
        return;
    }
    auto pc = cast(ClassInfo*) *ppv;
    scope (exit)
    {
        *ppv = null;
    }

    auto c = *pc;
    do
    {
        // Assume the destructor is @nogc. Leave it nothrow since the destructor
        // shouldn't throw and if it does, it is an error anyway.
        if (c.destructor)
        {
            (cast(void function (Object) nothrow @safe @nogc) c.destructor)(ob);
        }
    }
    while ((c = c.base) !is null);

    if (ppv[1]) // if monitor is not null
    {
        _d_monitordelete(cast(Object) ptr, true);
    }
}

/// Ditto.
void dispose(T)(shared Allocator allocator, auto ref T[] p)
{
    static if (hasElaborateDestructor!(typeof(p[0])))
    {
        import std.algorithm.iteration;
        p.each!(e => destroy(e));
    }
    () @trusted { allocator.deallocate(p); }();
    p = null;
}

unittest
{
    struct S
    {
        ~this()
        {
        }
    }
    auto p = cast(S[]) defaultAllocator.allocate(S.sizeof);

    defaultAllocator.dispose(p);
}
