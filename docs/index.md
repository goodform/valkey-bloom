# ValkeyBloom - Probablistic Datatypes Module for Valkey

This module provides two datatypes, a Scalable Bloom Filter and a Cuckoo Filter.
These datatypes are used to determine (with a given degree of certainty) whether
an item is present (or absent) from a collection.


## Quick Start Guide
[Use ValkeyBloom with valkey-cli](#use-valkeybloom-with-valkey-cli)

Note: You can also [build and load the module](#building-and-loading-valkeybloom) yourself.

You can find a command reference in [Bloom Commands.md](Bloom_Commands.md) and
[Cuckoo Commands](Cuckoo_Commands.md)


### Use ValkeyBloom with `valkey-cli`
```
docker exec -it valkey-bloom bash

# valkey-cli
# 127.0.0.1:6379> 
```

Start a new bloom filter by adding a new item
```
# 127.0.0.1:6379> BF.ADD newFilter foo
(integer) 1
``` 

 Checking if an item exists in the filter
```
# 127.0.0.1:6379> BF.EXISTS newFilter foo
(integer) 1
```


## Building and Loading ValkeyBloom

In order to use this module, build it using `make` and load it into Valkey.

### Loading

**Invoking valkey with the module loaded**

```
$ valkey-server --loadmodule /path/to/valkeybloom.so
```

You can find a command reference in [Bloom\_Commands.md](Bloom_Commands.md)
and [Cuckoo\_Commands.md](Cuckoo_Commands.md)


## Building

In order to use this module, build it using `make` and load it into Valkey.

### Module Options

You can adjust the default error ratio and the initial filter size (for bloom filters)
using the `ERROR_RATE` and `INITIAL_SIZE` options respectively when loading the
module, e.g.

```
$ valkey-server --loadmodule /path/to/valkeybloom.so INITIAL_SIZE 400 ERROR_RATE 0.004
```

The default error rate is `0.01` and the default initial capacity is `100`.

## Bloom vs. Cuckoo

Bloom Filters typically exhibit better performance and scalability when inserting
items (so if you're often adding items to your dataset then Bloom may be ideal),
whereas Cuckoo Filters are quicker on check operations and also allow deletions.
