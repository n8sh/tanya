/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Hash table.
 *
 * Copyright: Eugene Wissner 2018-2019.
 * License: $(LINK2 https://www.mozilla.org/en-US/MPL/2.0/,
 *                  Mozilla Public License, v. 2.0).
 * Authors: $(LINK2 mailto:info@caraus.de, Eugene Wissner)
 * Source: $(LINK2 https://github.com/caraus-ecms/tanya/blob/master/source/tanya/container/hashtable.d,
 *                 tanya/container/hashtable.d)
 */
module tanya.container.hashtable;

import tanya.algorithm.iteration;
import tanya.algorithm.mutation;
import tanya.container.array;
import tanya.container.entry;
import tanya.hash.lookup;
import tanya.memory.allocator;
import tanya.memory.lifetime;
import tanya.meta.trait;
import tanya.meta.transform;
import tanya.range.primitive;

/**
 * Bidirectional range whose element type is a tuple of a key and the
 * respective value.
 *
 * Params:
 *  T = Type of the internal hash storage.
 */
struct Range(T)
{
    private alias KV = CopyConstness!(T, T.Bucket.KV);
    static if (isMutable!T)
    {
        private alias DataRange = T.array.Range;
    }
    else
    {
        private alias DataRange = T.array.ConstRange;
    }
    private DataRange dataRange;

    @disable this();

    private this(DataRange dataRange)
    {
        while (!dataRange.empty && dataRange.front.status != BucketStatus.used)
        {
            dataRange.popFront();
        }
        while (!dataRange.empty && dataRange.back.status != BucketStatus.used)
        {
            dataRange.popBack();
        }
        this.dataRange = dataRange;
    }

    @property Range save()
    {
        return this;
    }

    @property bool empty() const
    {
        return this.dataRange.empty();
    }

    void popFront()
    in (!empty)
    in (this.dataRange.front.status == BucketStatus.used)
    out (; empty || this.dataRange.back.status == BucketStatus.used)
    {
        do
        {
            this.dataRange.popFront();
        }
        while (!empty && dataRange.front.status != BucketStatus.used);
    }

    void popBack()
    in (!empty)
    in (this.dataRange.back.status == BucketStatus.used)
    out (; empty || this.dataRange.back.status == BucketStatus.used)
    {
        do
        {
            this.dataRange.popBack();
        }
        while (!empty && dataRange.back.status != BucketStatus.used);
    }

    @property ref inout(KV) front() inout
    in (!empty)
    in (this.dataRange.front.status == BucketStatus.used)
    {
        return this.dataRange.front.kv;
    }

    @property ref inout(KV) back() inout
    in (!empty)
    in (this.dataRange.back.status == BucketStatus.used)
    {
        return this.dataRange.back.kv;
    }

    Range opIndex()
    {
        return typeof(return)(this.dataRange[]);
    }

    Range!(const T) opIndex() const
    {
        return typeof(return)(this.dataRange[]);
    }
}

/**
 * Bidirectional range iterating over the key of a $(D_PSYMBOL HashTable).
 *
 * Params:
 *  T = Type of the internal hash storage.
 */
struct ByKey(T)
{
    private alias Key = CopyConstness!(T, T.Key);
    static if (isMutable!T)
    {
        private alias DataRange = T.array.Range;
    }
    else
    {
        private alias DataRange = T.array.ConstRange;
    }
    private DataRange dataRange;

    @disable this();

    private this(DataRange dataRange)
    {
        while (!dataRange.empty && dataRange.front.status != BucketStatus.used)
        {
            dataRange.popFront();
        }
        while (!dataRange.empty && dataRange.back.status != BucketStatus.used)
        {
            dataRange.popBack();
        }
        this.dataRange = dataRange;
    }

    @property ByKey save()
    {
        return this;
    }

    @property bool empty() const
    {
        return this.dataRange.empty();
    }

    @property void popFront()
    in (!empty)
    in (this.dataRange.front.status == BucketStatus.used)
    out (; empty || this.dataRange.back.status == BucketStatus.used)
    {
        do
        {
            this.dataRange.popFront();
        }
        while (!empty && dataRange.front.status != BucketStatus.used);
    }

    @property void popBack()
    in (!empty)
    in (this.dataRange.back.status == BucketStatus.used)
    out (; empty || this.dataRange.back.status == BucketStatus.used)
    {
        do
        {
            this.dataRange.popBack();
        }
        while (!empty && dataRange.back.status != BucketStatus.used);
    }

    @property ref inout(Key) front() inout
    in (!empty)
    in (this.dataRange.front.status == BucketStatus.used)
    {
        return this.dataRange.front.key;
    }

    @property ref inout(Key) back() inout
    in (!empty)
    in (this.dataRange.back.status == BucketStatus.used)
    {
        return this.dataRange.back.key;
    }

    ByKey opIndex()
    {
        return typeof(return)(this.dataRange[]);
    }

    ByKey!(const T) opIndex() const
    {
        return typeof(return)(this.dataRange[]);
    }
}

/**
 * Bidirectional range iterating over the key of a $(D_PSYMBOL HashTable).
 *
 * Params:
 *  T = Type of the internal hash storage.
 */
struct ByValue(T)
{
    private alias Value = CopyConstness!(T, T.Value);
    static if (isMutable!T)
    {
        private alias DataRange = T.array.Range;
    }
    else
    {
        private alias DataRange = T.array.ConstRange;
    }
    private DataRange dataRange;

    @disable this();

    private this(DataRange dataRange)
    {
        while (!dataRange.empty && dataRange.front.status != BucketStatus.used)
        {
            dataRange.popFront();
        }
        while (!dataRange.empty && dataRange.back.status != BucketStatus.used)
        {
            dataRange.popBack();
        }
        this.dataRange = dataRange;
    }

    @property ByValue save()
    {
        return this;
    }

    @property bool empty() const
    {
        return this.dataRange.empty();
    }

    @property void popFront()
    in (!empty)
    in (this.dataRange.front.status == BucketStatus.used)
    out (; empty || this.dataRange.back.status == BucketStatus.used)
    {
        do
        {
            this.dataRange.popFront();
        }
        while (!empty && dataRange.front.status != BucketStatus.used);
    }

    @property void popBack()
    in (!empty)
    in (this.dataRange.back.status == BucketStatus.used)
    out (; empty || this.dataRange.back.status == BucketStatus.used)
    {
        do
        {
            this.dataRange.popBack();
        }
        while (!empty && dataRange.back.status != BucketStatus.used);
    }

    @property ref inout(Value) front() inout
    in (!empty)
    in (this.dataRange.front.status == BucketStatus.used)
    {
        return this.dataRange.front.kv.value;
    }

    @property ref inout(Value) back() inout
    in (!empty)
    in (this.dataRange.back.status == BucketStatus.used)
    {
        return this.dataRange.back.kv.value;
    }

    ByValue opIndex()
    {
        return typeof(return)(this.dataRange[]);
    }

    ByValue!(const T) opIndex() const
    {
        return typeof(return)(this.dataRange[]);
    }
}

/**
 * Hash table is a data structure that stores pairs of keys and values without
 * any particular order.
 *
 * This $(D_PSYMBOL HashTable) is implemented using closed hashing. Hash
 * collisions are resolved with linear probing.
 *
 * $(D_PARAM Key) should be hashable with $(D_PARAM hasher). $(D_PARAM hasher)
 * is a callable that accepts an argument of type $(D_PARAM Key) and returns a
 * hash value for it ($(D_KEYWORD size_t)).
 *
 * Params:
 *  Key    = Key type.
 *  Value  = Value type.
 *  hasher = Hash function for $(D_PARAM Key).
 */
struct HashTable(Key, Value, alias hasher = hash)
if (isHashFunction!(hasher, Key))
{
    private alias HashArray = .HashArray!(hasher, Key, Value);
    private alias Buckets = HashArray.Buckets;

    private HashArray data;

    /// Type of the key-value pair stored in the hash table.
    alias KeyValue = HashArray.Bucket.KV;

    /// The range types for $(D_PSYMBOL HashTable).
    alias Range = .Range!HashArray;

    /// ditto
    alias ConstRange = .Range!(const HashArray);

    /// ditto
    alias ByKey = .ByKey!(const HashArray);

    /// ditto
    alias ByValue = .ByValue!HashArray;

    /// ditto
    alias ConstByValue = .ByValue!(const HashArray);

    invariant (this.data.lengthIndex < primes.length);

    /**
     * Constructor.
     *
     * Params:
     *  n         = Minimum number of buckets.
     *  allocator = Allocator.
     *
     * Precondition: $(D_INLINECODE allocator !is null).
     */
    this(size_t n, shared Allocator allocator = defaultAllocator)
    in (allocator !is null)
    {
        this(allocator);
        this.data.rehash(n);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        auto hashTable = HashTable!(string, int)(5);
        assert(hashTable.capacity == 7);
    }

    /// ditto
    this(shared Allocator allocator)
    in (allocator !is null)
    {
        this.data = HashArray(allocator);
    }

    /**
     * Initializes this $(D_PARAM HashTable) from another one.
     *
     * If $(D_PARAM init) is passed by reference, it will be copied.
     * If $(D_PARAM init) is passed by value, it will be moved.
     *
     * Params:
     *  S         = Source set type.
     *  init      = Source set.
     *  allocator = Allocator.
     *
     * Precondition: $(D_INLINECODE allocator !is null).
     */
    this(S)(ref S init, shared Allocator allocator = defaultAllocator)
    if (is(Unqual!S == HashTable))
    in (allocator !is null)
    {
        this.data = HashArray(init.data, allocator);
    }

    /// ditto
    this(S)(S init, shared Allocator allocator = defaultAllocator)
    if (is(S == HashTable))
    in (allocator !is null)
    {
        this.data.move(init.data, allocator);
    }

    /**
     * Constructs the hash table from a forward range.
     *
     * Params:
     *  R         = Range type.
     *  range     = Forward range.
     *  allocator = Allocator.
     *
     * Precondition: $(D_INLINECODE allocator !is null).
     */
    this(R)(scope R range, shared Allocator allocator = defaultAllocator)
    if (isForwardRange!R && is(ElementType!R == KeyValue) && !isInfinite!R)
    in (allocator !is null)
    {
        this(allocator);
        insert(range);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        alias KeyValue = HashTable!(string, int).KeyValue;

        KeyValue[2] range = [KeyValue("one", 1), KeyValue("two", 2)];
        auto hashTable = HashTable!(string, int)(range[]);

        assert(hashTable["one"] == 1);
        assert(hashTable["two"] == 2);
    }

    /**
     * Initializes the hash table from a static array.
     *
     * Params:
     *  n         = Array size.
     *  array     = Static array.
     *  allocator = Allocator.
     *
     * Precondition: $(D_INLINECODE allocator !is null).
     */
    this(size_t n)(KeyValue[n] array,
         shared Allocator allocator = defaultAllocator)
    in (allocator !is null)
    {
        this(allocator);
        insert(array[]);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        alias KeyValue = HashTable!(string, int).KeyValue;
        auto hashTable = HashTable!(string, int)([KeyValue("one", 1), KeyValue("two", 2)]);

        assert(hashTable["one"] == 1);
        assert(hashTable["two"] == 2);
    }

    /**
     * Assigns another hash table.
     *
     * If $(D_PARAM that) is passed by reference, it will be copied.
     * If $(D_PARAM that) is passed by value, it will be moved.
     *
     * Params:
     *  S    = Content type.
     *  that = The value should be assigned.
     *
     * Returns: $(D_KEYWORD this).
     */
    ref typeof(this) opAssign(S)(ref S that)
    if (is(Unqual!S == HashTable))
    {
        this.data = that.data;
        return this;
    }

    /// ditto
    ref typeof(this) opAssign(S)(S that) @trusted
    if (is(S == HashTable))
    {
        this.data.swap(that.data);
        return this;
    }

    /**
     * Returns: Used allocator.
     *
     * Postcondition: $(D_INLINECODE allocator !is null)
     */
    @property shared(Allocator) allocator() const
    out (allocator; allocator !is null)
    {
        return this.data.array.allocator;
    }

    /**
     * Maximum amount of elements this $(D_PSYMBOL HashTable) can hold without
     * resizing and rehashing. Note that it doesn't mean that the
     * $(D_PSYMBOL Set) will hold $(I exactly) $(D_PSYMBOL capacity) elements.
     * $(D_PSYMBOL capacity) tells the size of the container under a best-case
     * distribution of elements.
     *
     * Returns: $(D_PSYMBOL HashTable) capacity.
     */
    @property size_t capacity() const
    {
        return this.data.capacity;
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        assert(hashTable.capacity == 0);

        hashTable["eight"] = 8;
        assert(hashTable.capacity == 3);
    }

    /**
     * Returns the number of elements in the container.
     *
     * Returns: The number of elements in the container.
     */
    @property size_t length() const
    {
        return this.data.length;
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        assert(hashTable.length == 0);

        hashTable["eight"] = 8;
        assert(hashTable.length == 1);
    }

    /**
     * Tells whether the container contains any elements.
     *
     * Returns: Whether the container is empty.
     */
    @property bool empty() const
    {
        return length == 0;
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        assert(hashTable.empty);
        hashTable["five"] = 5;
        assert(!hashTable.empty);
    }

    /**
     * Removes all elements.
     */
    void clear()
    {
        this.data.clear();
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        hashTable["five"] = 5;
        assert(!hashTable.empty);
        hashTable.clear();
        assert(hashTable.empty);
    }

    /**
     * Returns current bucket count in the container.
     *
     * Bucket count equals to the number of the elements can be saved in the
     * container in the best case scenario for key distribution, i.d. every key
     * has a unique hash value. In a worse case the bucket count can be less
     * than the number of elements stored in the container.
     *
     * Returns: Current bucket count.
     *
     * See_Also: $(D_PSYMBOL rehash).
     */
    @property size_t bucketCount() const
    {
        return this.data.bucketCount;
    }

    /// The maximum number of buckets the container can have.
    enum size_t maxBucketCount = primes[$ - 1];

    /**
     * Inserts a new value at $(D_PARAM key) or reassigns the element if
     * $(D_PARAM key) already exists in the hash table.
     *
     * Params:
     *  key   = The key to insert the value at.
     *  value = The value to be inserted.
     *
     * Returns: Just inserted element.
     */
    ref Value opIndexAssign()(auto ref Value value, auto ref Key key)
    {
        auto e = ((ref v) @trusted => &this.data.insert(v))(key);
        if (e.status != BucketStatus.used)
        {
            static if (__traits(isRef, key))
            {
                e.key = key;
            }
            else
            {
                e.moveKey(key);
            }
        }
        static if (__traits(isRef, value))
        {
            return e.kv.value = value;
        }
        else
        {
            return e.kv.value = move(value);
        }
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        assert("Pachycephalosaurus" !in hashTable);

        hashTable["Pachycephalosaurus"] = 6;
        assert(hashTable.length == 1);
        assert("Pachycephalosaurus" in hashTable);

        hashTable["Pachycephalosaurus"] = 6;
        assert(hashTable.length == 1);
        assert("Pachycephalosaurus" in hashTable);
    }

    /**
     * Inserts a new element in the hash table.
     *
     * If the element with the same key was already in the table, it reassigns
     * it with the new value, but $(D_PSYMBOL insert) returns `0`. Otherwise
     * `1` is returned.
     *
     * Params:
     *  keyValue = Key/value pair.
     *
     * Returns: The number of the inserted elements with a unique key.
     */
    size_t insert()(ref KeyValue keyValue)
    {
        auto e = ((ref v) @trusted => &this.data.insert(v))(keyValue.key);
        size_t inserted;
        if (e.status != BucketStatus.used)
        {
            e.key = keyValue.key;
            inserted = 1;
        }
        e.kv.value = keyValue.value;
        return inserted;
    }

    /// ditto
    size_t insert()(KeyValue keyValue)
    {
        auto e = ((ref v) @trusted => &this.data.insert(v))(keyValue.key);
        size_t inserted;
        if (e.status != BucketStatus.used)
        {
            e.moveKey(keyValue.key);
            inserted = 1;
        }
        move(keyValue.value, e.kv.value);
        return inserted;
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;

        assert(hashTable.insert(hashTable.KeyValue("number", 1)) == 1);
        assert(hashTable["number"] == 1);
        assert(hashTable.insert(hashTable.KeyValue("number", 2)) == 0);
        assert(hashTable["number"] == 2);
    }

    /**
     * Inserts a forward range of key/value pairs into the hash table.
     *
     * If some of the elements in the $(D_PARAM range) have the same key, they
     * are reassigned but are not counted as inserted elements. So the value
     * returned by this function will be less than the range length.
     *
     * Params:
     *  R     = Range type.
     *  range = Forward range.
     *
     * Returns: The number of the inserted elements with a unique key.
     */
    size_t insert(R)(scope R range)
    if (isForwardRange!R && is(ElementType!R == KeyValue) && !isInfinite!R)
    {
        return foldl!((acc, x) => acc + insert(x))(range, 0U);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;

        hashTable.KeyValue[2] range = [
            hashTable.KeyValue("one", 1),
            hashTable.KeyValue("two", 2),
        ];

        assert(hashTable.insert(range[]) == 2);
        assert(hashTable["one"] == 1);
        assert(hashTable["two"] == 2);
    }

    /**
     * Find the element with the key $(D_PARAM key).
     *
     * Params:
     *  T   = Type comparable with the key type, used for the lookup.
     *  key = The key to be find.
     *
     * Returns: The value associated with $(D_PARAM key).
     *
     * Precondition: Element with $(D_PARAM key) is in this hash table.
     */
    ref Value opIndex(T)(auto ref const T key)
    if (ifTestable!(T, a => Key.init == a))
    {
        const code = this.data.locateBucket(key);

        for (auto range = this.data.array[code .. $]; !range.empty; range.popFront())
        {
            if (key == range.front.key)
            {
                return range.front.kv.value;
            }
        }
        assert(false, "Range violation");
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        hashTable["Triceratops"] = 7;
        assert(hashTable["Triceratops"] == 7);
    }

    /**
     * Removes the element with the key $(D_PARAM key).
     *
     * The method returns the number of elements removed. Since
     * the hash table contains only unique keys, $(D_PARAM remove) always
     * returns `1` if an element with the $(D_PARAM key) was found, `0`
     * otherwise.
     *
     * Params:
     *  key = The key to be removed.
     *
     * Returns: Number of the removed elements.
     */
    size_t remove(Key key)
    {
        return this.data.remove(key);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        hashTable["Euoplocephalus"] = 6;

        assert("Euoplocephalus" in hashTable);
        assert(hashTable.remove("Euoplocephalus") == 1);
        assert(hashTable.remove("Euoplocephalus") == 0);
        assert("Euoplocephalus" !in hashTable);
    }

    /**
     * Looks for $(D_PARAM key) in this hash table.
     *
     * Params:
     *  T   = Type comparable with the key type, used for the lookup.
     *  key = The key to look for.
     *
     * Returns: $(D_KEYWORD true) if $(D_PARAM key) exists in the hash table,
     *          $(D_KEYWORD false) otherwise.
     */
    bool opBinaryRight(string op : "in", T)(auto ref const T key) const
    if (ifTestable!(T, a => Key.init == a))
    {
        return key in this.data;
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;

        assert("Shantungosaurus" !in hashTable);
        hashTable["Shantungosaurus"] = 15;
        assert("Shantungosaurus" in hashTable);

        assert("Ceratopsia" !in hashTable);
    }

    /**
     * Sets the number of buckets in the container to at least $(D_PARAM n)
     * and rearranges all the elements according to their hash values.
     *
     * If $(D_PARAM n) is greater than the current $(D_PSYMBOL bucketCount)
     * and lower than or equal to $(D_PSYMBOL maxBucketCount), a rehash is
     * forced.
     *
     * If $(D_PARAM n) is greater than $(D_PSYMBOL maxBucketCount),
     * $(D_PSYMBOL maxBucketCount) is used instead as a new number of buckets.
     *
     * If $(D_PARAM n) is less than or equal to the current
     * $(D_PSYMBOL bucketCount), the function may have no effect.
     *
     * Rehashing is automatically performed whenever the container needs space
     * to insert new elements.
     *
     * Params:
     *  n = Minimum number of buckets.
     */
    void rehash(size_t n)
    {
        this.data.rehash(n);
    }

    /**
     * Returns a bidirectional range whose element type is a tuple of a key and
     * the respective value.
     *
     * Returns: A bidirectional range that iterates over the container.
     */
    Range opIndex()
    {
        return typeof(return)(this.data.array[]);
    }

    /// ditto
    ConstRange opIndex() const
    {
        return typeof(return)(this.data.array[]);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        assert(hashTable[].empty);

        hashTable["Iguanodon"] = 9;
        assert(!hashTable[].empty);
        assert(hashTable[].front == hashTable.KeyValue("Iguanodon", 9));
        assert(hashTable[].back == hashTable.KeyValue("Iguanodon", 9));
    }

    /**
     * Returns a bidirectional range that iterats over the keys of this
     * $(D_PSYMBOL HashTable).
     *
     * This function always returns a $(D_KEYWORD const) range, since changing
     * a key of a hash table would probably change its hash value and require
     * rehashing.
     *
     * Returns: $(D_KEYWORD const) bidirectional range that iterates over the
     *          keys of the container.
     *
     * See_Also: $(D_PSYMBOL byValue).
     */
    ByKey byKey() const
    {
        return typeof(return)(this.data.array[]);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        hashTable["one"] = 1;
        hashTable["two"] = 2;

        auto byKey = hashTable.byKey();
        assert(!byKey.empty);

        assert(byKey.front == "one" || byKey.front == "two");
        assert(byKey.back == "one" || byKey.back == "two");
        assert(byKey.front != byKey.back);

        byKey.popFront();
        assert(byKey.front == byKey.back);

        byKey.popBack();
        assert(byKey.empty);
    }

    /**
     * Returns a bidirectional range that iterats over the values of this
     * $(D_PSYMBOL HashTable).
     *
     * Returns: A bidirectional range that iterates over the values of the
     *          container.
     *
     * See_Also: $(D_PSYMBOL byKey).
     */
    ByValue byValue()
    {
        return typeof(return)(this.data.array[]);
    }

    /// ditto
    ConstByValue byValue() const
    {
        return typeof(return)(this.data.array[]);
    }

    ///
    @nogc nothrow pure @safe unittest
    {
        HashTable!(string, int) hashTable;
        hashTable["one"] = 1;
        hashTable["two"] = 2;

        auto byValue = hashTable.byValue();
        assert(!byValue.empty);

        assert(byValue.front == 1 || byValue.front == 2);
        assert(byValue.back == 1 || byValue.back == 2);
        assert(byValue.front != byValue.back);

        byValue.popFront();
        assert(byValue.front == byValue.back);

        byValue.popBack();
        assert(byValue.empty);
    }
}

@nogc nothrow pure @safe unittest
{
    auto dinos = HashTable!(string, int)(17);
    assert(dinos.empty);

    dinos["Ornithominus"] = 4;
    dinos["Tyrannosaurus"] = 12;
    dinos["Deinonychus"] = 3;
    dinos["Stegosaurus"] = 6;
    dinos["Brachiosaurus"] = 25;

    assert(dinos.length == 5);
    assert(dinos["Ornithominus"] == 4);
    assert(dinos["Stegosaurus"] == 6);
    assert(dinos["Deinonychus"] == 3);
    assert(dinos["Tyrannosaurus"] == 12);
    assert(dinos["Brachiosaurus"] == 25);

    dinos.clear();
    assert(dinos.empty);
}
