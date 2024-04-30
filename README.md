# ValkeyBloom - Bloom Filter Module for Valkey

This module provides two probabalistic data structures as Valkey data types:
**Bloom Filters** and **Cuckoo Filters**. These two structures are similar in
their purpose but have different performance and functionality characteristics

You can find a command reference in [Bloom_Commands.md](docs/Bloom_Commands.md)

Note: You can also [build and load the module](#building-and-loading-valkeybloom) yourself.

### Use ValkeyBloom with `valkey-cli`

## Quick Start Guide

```
# valkey-cli
# 127.0.0.1:6379> module load /path/to/valkeybloom.so
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

You can find a command reference in [docs/Bloom_Commands.md](docs/Bloom_Commands.md)

