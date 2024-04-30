#include "valkeymodule.h"
#include "sb.h"
#include "cf.h"
#include "version.h"

#include <assert.h>
#include <strings.h> // strncasecmp
#include <string.h>
#include <ctype.h>

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
/// Valkey Commands                                                          ///
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
static ValkeyModuleType *BFType;
static ValkeyModuleType *CFType;
static double BFDefaultErrorRate = 0.01;
static size_t BFDefaultInitCapacity = 100;
static size_t CFDefaultInitCapacity = 1000;
static size_t CFMaxExpansions = 1024;
static int rsStrcasecmp(const ValkeyModuleString *rs1, const char *s2);

typedef enum { SB_OK = 0, SB_MISSING, SB_EMPTY, SB_MISMATCH } lookupStatus;

typedef struct {
    long long capacity;
    double error_rate;
    int autocreate;
    // int must_exist;
    int is_multi;
} BFInsertOptions;

static int bfInsertCommon(ValkeyModuleCtx *ctx, ValkeyModuleString *keystr, ValkeyModuleString **items,
                          size_t nitems, const BFInsertOptions *options);

static int getValue(ValkeyModuleKey *key, ValkeyModuleType *expType, void **sbout) {
    *sbout = NULL;
    if (key == NULL) {
        return SB_MISSING;
    }
    int type = ValkeyModule_KeyType(key);
    if (type == VALKEYMODULE_KEYTYPE_EMPTY) {
        return SB_EMPTY;
    } else if (type == VALKEYMODULE_KEYTYPE_MODULE &&
               ValkeyModule_ModuleTypeGetType(key) == expType) {
        *sbout = ValkeyModule_ModuleTypeGetValue(key);
        return SB_OK;
    } else {
        return SB_MISMATCH;
    }
}

static int bfGetChain(ValkeyModuleKey *key, SBChain **sbout) {
    return getValue(key, BFType, (void **)sbout);
}

static int cfGetFilter(ValkeyModuleKey *key, CuckooFilter **cfout) {
    return getValue(key, CFType, (void **)cfout);
}

static const char *statusStrerror(int status) {
    switch (status) {
    case SB_MISSING:
    case SB_EMPTY:
        return "ERR not found";
    case SB_MISMATCH:
        return VALKEYMODULE_ERRORMSG_WRONGTYPE;
    case SB_OK:
        return "ERR item exists";
    default:
        return "Unknown error";
    }
}

/**
 * Common function for adding one or more items to a bloom filter.
 * capacity and error rate must not be 0.
 */
static SBChain *bfCreateChain(ValkeyModuleKey *key, double error_rate, size_t capacity) {
    SBChain *sb = SB_NewChain(capacity, error_rate, BLOOM_OPT_FORCE64);
    if (sb != NULL) {
        ValkeyModule_ModuleTypeSetValue(key, BFType, sb);
    }
    return sb;
}

static CuckooFilter *cfCreate(ValkeyModuleKey *key, size_t capacity) {
    CuckooFilter *cf = ValkeyModule_Calloc(1, sizeof(*cf));
    if (CuckooFilter_Init(cf, capacity) != 0) {
        ValkeyModule_Free(cf);
        cf = NULL;
    }
    ValkeyModule_ModuleTypeSetValue(key, CFType, cf);
    return cf;
}

/**
 * Reserves a new empty filter with custom parameters:
 * BF.RESERVE <KEY> <ERROR_RATE (double)> <INITIAL_CAPACITY (int)>
 */
static int BFReserve_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);

    if (argc != 4) {
        ValkeyModule_WrongArity(ctx);
        return VALKEYMODULE_ERR;
    }

    double error_rate;
    if (ValkeyModule_StringToDouble(argv[2], &error_rate) != VALKEYMODULE_OK) {
        return ValkeyModule_ReplyWithError(ctx, "ERR bad error rate");
    }

    long long capacity;
    if (ValkeyModule_StringToLongLong(argv[3], &capacity) != VALKEYMODULE_OK ||
        capacity >= UINT32_MAX) {
        return ValkeyModule_ReplyWithError(ctx, "ERR bad capacity");
    }

    if (error_rate == 0 || capacity == 0) {
        return ValkeyModule_ReplyWithError(ctx, "ERR capacity and error must not be 0");
    }

    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ | VALKEYMODULE_WRITE);
    SBChain *sb;
    int status = bfGetChain(key, &sb);
    if (status != SB_EMPTY) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    if (bfCreateChain(key, error_rate, capacity) == NULL) {
        ValkeyModule_ReplyWithSimpleString(ctx, "ERR could not create filter");
    } else {
        ValkeyModule_ReplyWithSimpleString(ctx, "OK");
    }
    return VALKEYMODULE_OK;
}

static int isMulti(const ValkeyModuleString *rs) {
    size_t n;
    const char *s = ValkeyModule_StringPtrLen(rs, &n);
    return s[3] == 'm' || s[3] == 'M';
}

/**
 * Check for the existence of an item
 * BF.CHECK <KEY>
 * Returns true or false
 */
static int BFCheck_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    int is_multi = isMulti(argv[0]);

    if ((is_multi == 0 && argc != 3) || (is_multi && argc < 3)) {
        ValkeyModule_WrongArity(ctx);
        return VALKEYMODULE_ERR;
    }

    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ);
    SBChain *sb;
    int status = bfGetChain(key, &sb);

    int is_empty = 0;
    if (status != SB_OK) {
        is_empty = 1;
    }

    // Check if it exists?
    if (is_multi) {
        ValkeyModule_ReplyWithArray(ctx, argc - 2);
    }

    for (size_t ii = 2; ii < argc; ++ii) {
        if (is_empty == 1) {
            ValkeyModule_ReplyWithLongLong(ctx, 0);
        } else {
            size_t n;
            const char *s = ValkeyModule_StringPtrLen(argv[ii], &n);
            int exists = SBChain_Check(sb, s, n);
            ValkeyModule_ReplyWithLongLong(ctx, exists);
        }
    }

    return VALKEYMODULE_OK;
}

static int bfInsertCommon(ValkeyModuleCtx *ctx, ValkeyModuleString *keystr, ValkeyModuleString **items,
                          size_t nitems, const BFInsertOptions *options) {
    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, keystr, VALKEYMODULE_READ | VALKEYMODULE_WRITE);
    SBChain *sb;
    int status = bfGetChain(key, &sb);
    if (status == SB_EMPTY && options->autocreate) {
        sb = bfCreateChain(key, options->error_rate, options->capacity);
        if (sb == NULL) {
            return ValkeyModule_ReplyWithError(ctx, "ERR could not create filter");
        }
    } else if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    if (options->is_multi) {
        ValkeyModule_ReplyWithArray(ctx, nitems);
    }

    for (size_t ii = 0; ii < nitems; ++ii) {
        size_t n;
        const char *s = ValkeyModule_StringPtrLen(items[ii], &n);
        int rv = SBChain_Add(sb, s, n);
        ValkeyModule_ReplyWithLongLong(ctx, !!rv);
    }
    return VALKEYMODULE_OK;
}

/**
 * Adds items to an existing filter. Creates a new one on demand if it doesn't exist.
 * BF.ADD <KEY> ITEMS...
 * Returns an array of integers. The nth element is either 1 or 0 depending on whether it was newly
 * added, or had previously existed, respectively.
 */
static int BFAdd_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);
    BFInsertOptions options = {
        .capacity = BFDefaultInitCapacity, .error_rate = BFDefaultErrorRate, .autocreate = 1};
    options.is_multi = isMulti(argv[0]);

    if ((options.is_multi && argc < 3) || (!options.is_multi && argc != 3)) {
        return ValkeyModule_WrongArity(ctx);
    }
    return bfInsertCommon(ctx, argv[1], argv + 2, argc - 2, &options);
}
/**
 * BF.INSERT {filter} [ERROR {rate} CAPACITY {cap}] [NOCREATE] ITEMS {item} {item}
 * ..
 * -> (Array) (or error )
 */
static int BFInsert_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);
    BFInsertOptions options = {.capacity = BFDefaultInitCapacity,
                               .error_rate = BFDefaultErrorRate,
                               .autocreate = 1,
                               .is_multi = 1};
    int items_index = -1;

    // Scan the arguments
    if (argc < 4) {
        return ValkeyModule_WrongArity(ctx);
    }

    size_t cur_pos = 2;
    while (cur_pos < argc && items_index < 0) {
        size_t arglen;
        const char *argstr = ValkeyModule_StringPtrLen(argv[cur_pos], &arglen);

        switch (tolower(*argstr)) {
        case 'i':
            items_index = ++cur_pos;
            break;

        case 'e':
            if (++cur_pos == argc) {
                return ValkeyModule_WrongArity(ctx);
            }
            if (ValkeyModule_StringToDouble(argv[cur_pos++], &options.error_rate) !=
                VALKEYMODULE_OK) {
                return ValkeyModule_ReplyWithError(ctx, "Bad error rate");
            }
            break;

        case 'c':
            if (++cur_pos == argc) {
                return ValkeyModule_WrongArity(ctx);
            }
            if (ValkeyModule_StringToLongLong(argv[cur_pos++], &options.capacity) !=
                VALKEYMODULE_OK) {
                return ValkeyModule_ReplyWithError(ctx, "Bad capacity");
            }
            break;

        case 'n':
            options.autocreate = 0;
            cur_pos++;
            break;

        default:
            return ValkeyModule_ReplyWithError(ctx, "Unknown argument received");
        }
    }
    if (items_index < 0 || items_index == argc) {
        return ValkeyModule_WrongArity(ctx);
    }
    return bfInsertCommon(ctx, argv[1], argv + items_index, argc - items_index, &options);
}

/**
 * BF.DEBUG KEY
 * returns some information about the bloom filter.
 */
static int BFInfo_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);

    if (argc != 2) {
        ValkeyModule_WrongArity(ctx);
        return VALKEYMODULE_ERR;
    }

    const SBChain *sb = NULL;
    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ);
    int status = bfGetChain(key, (SBChain **)&sb);
    if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    // Start writing info
    ValkeyModule_ReplyWithArray(ctx, 1 + sb->nfilters);

    ValkeyModuleString *info_s = ValkeyModule_CreateStringPrintf(ctx, "size:%zu", sb->size);
    ValkeyModule_ReplyWithString(ctx, info_s);
    ValkeyModule_FreeString(ctx, info_s);

    for (size_t ii = 0; ii < sb->nfilters; ++ii) {
        const SBLink *lb = sb->filters + ii;
        info_s = ValkeyModule_CreateStringPrintf(
            ctx, "bytes:%zu bits:%llu hashes:%u hashwidth:%u capacity:%u size:%lu ratio:%g",
            lb->inner.bytes, lb->inner.bits ? lb->inner.bits : 1LLU << lb->inner.n2,
            lb->inner.hashes, sb->options & BLOOM_OPT_FORCE64 ? 64 : 32, lb->inner.entries,
            lb->size, lb->inner.error);
        ValkeyModule_ReplyWithString(ctx, info_s);
        ValkeyModule_FreeString(ctx, info_s);
    }

    return VALKEYMODULE_OK;
}

#define MAX_SCANDUMP_SIZE 10485760 // 10MB

/**
 * BF.SCANDUMP <KEY> <ITER>
 * Returns an (iterator,data) pair which can be used for LOADCHUNK later on
 */
static int BFScanDump_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    if (argc != 3) {
        return ValkeyModule_WrongArity(ctx);
    }
    const SBChain *sb = NULL;
    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ);
    int status = bfGetChain(key, (SBChain **)&sb);
    if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    long long iter;
    if (ValkeyModule_StringToLongLong(argv[2], &iter) != VALKEYMODULE_OK) {
        return ValkeyModule_ReplyWithError(ctx, "Second argument must be numeric");
    }

    ValkeyModule_ReplyWithArray(ctx, 2);

    if (iter == 0) {
        size_t hdrlen;
        char *hdr = SBChain_GetEncodedHeader(sb, &hdrlen);
        ValkeyModule_ReplyWithLongLong(ctx, SB_CHUNKITER_INIT);
        ValkeyModule_ReplyWithStringBuffer(ctx, (const char *)hdr, hdrlen);
        SB_FreeEncodedHeader(hdr);
    } else {
        size_t bufLen = 0;
        const char *buf = SBChain_GetEncodedChunk(sb, &iter, &bufLen, MAX_SCANDUMP_SIZE);
        ValkeyModule_ReplyWithLongLong(ctx, iter);
        ValkeyModule_ReplyWithStringBuffer(ctx, buf, bufLen);
    }
    return VALKEYMODULE_OK;
}

/**
 * BF.LOADCHUNK <KEY> <ITER> <DATA>
 * Incrementally loads a bloom filter.
 */
static int BFLoadChunk_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);

    if (argc != 4) {
        return ValkeyModule_WrongArity(ctx);
    }

    long long iter;
    if (ValkeyModule_StringToLongLong(argv[2], &iter) != VALKEYMODULE_OK) {
        return ValkeyModule_ReplyWithError(ctx, "ERR Second argument must be numeric");
    }

    size_t bufLen;
    const char *buf = ValkeyModule_StringPtrLen(argv[3], &bufLen);

    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ | VALKEYMODULE_WRITE);
    SBChain *sb;
    int status = bfGetChain(key, &sb);
    if (status == SB_EMPTY && iter == 1) {
        const char *errmsg;
        SBChain *sb = SB_NewChainFromHeader(buf, bufLen, &errmsg);
        if (!sb) {
            return ValkeyModule_ReplyWithError(ctx, errmsg);
        } else {
            ValkeyModule_ModuleTypeSetValue(key, BFType, sb);
            return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
        }
    } else if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    assert(sb);

    const char *errMsg;
    if (SBChain_LoadEncodedChunk(sb, iter, buf, bufLen, &errMsg) != 0) {
        return ValkeyModule_ReplyWithError(ctx, errMsg);
    } else {
        return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
    }
}

/** CF.RESERVE <KEY> <CAPACITY> */
static int CFReserve_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);
    //
    if (argc != 3) {
        return ValkeyModule_WrongArity(ctx);
    }

    long long capacity;
    if (ValkeyModule_StringToLongLong(argv[2], &capacity)) {
        return ValkeyModule_ReplyWithError(ctx, "Bad capacity");
    }

    CuckooFilter *cf;
    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ | VALKEYMODULE_WRITE);
    int status = cfGetFilter(key, &cf);
    if (status != SB_EMPTY) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    cf = cfCreate(key, capacity);
    if (cf == NULL) {
        return ValkeyModule_ReplyWithError(ctx, "Couldn't create Cuckoo Filter");
    } else {
        return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
    }
}

typedef struct {
    int is_nx;
    int autocreate;
    int is_multi;
    long long capacity;
} CFInsertOptions;

static int cfInsertCommon(ValkeyModuleCtx *ctx, ValkeyModuleString *keystr, ValkeyModuleString **items,
                          size_t nitems, const CFInsertOptions *options) {
    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, keystr, VALKEYMODULE_READ | VALKEYMODULE_WRITE);
    CuckooFilter *cf = NULL;
    int status = cfGetFilter(key, &cf);

    if (status == SB_EMPTY && options->autocreate) {
        if ((cf = cfCreate(key, options->capacity)) == NULL) {
            return ValkeyModule_ReplyWithError(ctx, "Could not create filter");
        }
    } else if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    if (cf->numFilters >= CFMaxExpansions) {
        // Ensure that adding new elements does not cause heavy expansion.
        // We might want to find a way to better distinguish legitimate from malicious
        // additions.
        return ValkeyModule_ReplyWithError(ctx, "Maximum expansions reached");
    }

    // See if we can add the element
    if (options->is_multi) {
        ValkeyModule_ReplyWithArray(ctx, nitems);
    }

    for (size_t ii = 0; ii < nitems; ++ii) {
        size_t elemlen;
        const char *elem = ValkeyModule_StringPtrLen(items[ii], &elemlen);
        CuckooHash hash = CUCKOO_GEN_HASH(elem, elemlen);
        CuckooInsertStatus insStatus;
        if (options->is_nx) {
            insStatus = CuckooFilter_InsertUnique(cf, hash);
        } else {
            insStatus = CuckooFilter_Insert(cf, hash);
        }
        if (insStatus == CuckooInsert_Inserted) {
            ValkeyModule_ReplyWithLongLong(ctx, 1);
        } else if (insStatus == CuckooInsert_Exists) {
            ValkeyModule_ReplyWithLongLong(ctx, 0);
        } else if (insStatus == CuckooInsert_NoSpace) {
            if (!options->is_multi) {
                return ValkeyModule_ReplyWithError(ctx, "Filter is full");
            } else {
                ValkeyModule_ReplyWithLongLong(ctx, -1);
            }
        } else {
            // Should never happen
            ValkeyModule_ReplyWithLongLong(ctx, -2);
        }
    }

    return VALKEYMODULE_OK;
}

/**
 * CF.ADD <KEY> <ELEM>
 *
 * Adds an item to a cuckoo filter, potentially creating a new cuckoo filter
 */
static int CFAdd_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);
    CFInsertOptions options = {.autocreate = 1, .capacity = CFDefaultInitCapacity, .is_multi = 0};
    size_t cmdlen;
    const char *cmdstr = ValkeyModule_StringPtrLen(argv[0], &cmdlen);
    options.is_nx = tolower(cmdstr[cmdlen - 1]) == 'x';
    if (argc != 3) {
        return ValkeyModule_WrongArity(ctx);
    }
    return cfInsertCommon(ctx, argv[1], argv + 2, 1, &options);
}

/**
 * CF.INSERT <KEY> [NOCREATE] [CAPACITY <cap>] ITEMS <item...>
 */
static int CFInsert_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);
    CFInsertOptions options = {.autocreate = 1, .capacity = CFDefaultInitCapacity, .is_multi = 1};
    size_t cmdlen;
    const char *cmdstr = ValkeyModule_StringPtrLen(argv[0], &cmdlen);
    options.is_nx = tolower(cmdstr[cmdlen - 1]) == 'x';
    // Need <cmd> <key> <ITEMS> <n..> -- at least 4 arguments
    if (argc < 4) {
        return ValkeyModule_WrongArity(ctx);
    }

    size_t cur_pos = 2;
    int items_pos = -1;
    while (cur_pos < argc && items_pos < 0) {
        size_t n;
        const char *argstr = ValkeyModule_StringPtrLen(argv[cur_pos], &n);
        switch (tolower(*argstr)) {
        case 'c':
            if (++cur_pos == argc) {
                return ValkeyModule_WrongArity(ctx);
            }
            if (ValkeyModule_StringToLongLong(argv[cur_pos++], &options.capacity) !=
                VALKEYMODULE_OK) {
                return ValkeyModule_ReplyWithError(ctx, "Bad capacity");
            }
            break;
        case 'i':
            // Begin item list
            items_pos = ++cur_pos;
            break;
        case 'n':
            options.autocreate = 0;
            cur_pos++;
            break;
        default:
            return ValkeyModule_ReplyWithError(ctx, "Unknown argument received");
        }
    }

    if (items_pos < 0 || items_pos == argc) {
        return ValkeyModule_WrongArity(ctx);
    }
    return cfInsertCommon(ctx, argv[1], argv + items_pos, argc - items_pos, &options);
}

static int isCount(ValkeyModuleString *s) {
    size_t n;
    const char *ss = ValkeyModule_StringPtrLen(s, &n);
    return toupper(ss[n - 1]) == 'T';
}

/**
 * Copy-paste from BFCheck :'(
 */
static int CFCheck_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);

    int is_multi = isMulti(argv[0]);
    int is_count = isCount(argv[0]);

    if ((is_multi == 0 && argc != 3) || (is_multi && argc < 3)) {
        return ValkeyModule_WrongArity(ctx);
    }

    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ);
    CuckooFilter *cf;
    int status = cfGetFilter(key, &cf);

    int is_empty = 0;
    if (status != SB_OK) {
        is_empty = 1;
    }

    // Check if it exists?
    if (is_multi) {
        ValkeyModule_ReplyWithArray(ctx, argc - 2);
    }

    for (size_t ii = 2; ii < argc; ++ii) {
        if (is_empty == 1) {
            ValkeyModule_ReplyWithLongLong(ctx, 0);
        } else {
            size_t n;
            const char *s = ValkeyModule_StringPtrLen(argv[ii], &n);
            CuckooHash hash = CUCKOO_GEN_HASH(s, n);
            long long rv;
            if (is_count) {
                rv = CuckooFilter_Count(cf, hash);
            } else {
                rv = CuckooFilter_Check(cf, hash);
            }
            ValkeyModule_ReplyWithLongLong(ctx, rv);
        }
    }
    return VALKEYMODULE_OK;
}

static int CFDel_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    ValkeyModule_ReplicateVerbatim(ctx);

    if (argc != 3) {
        return ValkeyModule_WrongArity(ctx);
    }

    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ | VALKEYMODULE_WRITE);
    CuckooFilter *cf;
    int status = cfGetFilter(key, &cf);
    if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, "Not found");
    }

    size_t elemlen;
    const char *elem = ValkeyModule_StringPtrLen(argv[2], &elemlen);
    CuckooHash hash = CUCKOO_GEN_HASH(elem, elemlen);
    return ValkeyModule_ReplyWithLongLong(ctx, CuckooFilter_Delete(cf, hash));
}

static void fillCFHeader(CFHeader *header, const CuckooFilter *cf) {
    *header = (CFHeader){.numItems = cf->numItems,
                         .numBuckets = cf->numBuckets,
                         .numDeletes = cf->numDeletes,
                         .numFilters = cf->numFilters};
}

static int CFScanDump_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);

    if (argc != 3) {
        return ValkeyModule_WrongArity(ctx);
    }

    long long pos;
    if (ValkeyModule_StringToLongLong(argv[2], &pos) != VALKEYMODULE_OK) {
        return ValkeyModule_ReplyWithError(ctx, "Invalid position");
    }

    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ);
    CuckooFilter *cf;
    int status = cfGetFilter(key, &cf);
    if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    ValkeyModule_ReplyWithArray(ctx, 2);
    if (!cf->numItems) {
        ValkeyModule_ReplyWithLongLong(ctx, 0);
        ValkeyModule_ReplyWithNull(ctx);
        return VALKEYMODULE_OK;
    }

    // Start
    if (pos == 0) {
        CFHeader header;
        fillCFHeader(&header, cf);
        ValkeyModule_ReplyWithLongLong(ctx, 1);
        ValkeyModule_ReplyWithStringBuffer(ctx, (const char *)&header, sizeof header);
        return VALKEYMODULE_OK;
    }

    size_t chunkLen;
    const char *chunk = CF_GetEncodedChunk(cf, &pos, &chunkLen, MAX_SCANDUMP_SIZE);
    if (chunk == NULL) {
        ValkeyModule_ReplyWithLongLong(ctx, 0);
        ValkeyModule_ReplyWithNull(ctx);
    } else {
        ValkeyModule_ReplyWithLongLong(ctx, pos);
        ValkeyModule_ReplyWithStringBuffer(ctx, chunk, chunkLen);
    }
    return VALKEYMODULE_OK;
}

static int CFLoadChunk_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);

    if (argc != 4) {
        return ValkeyModule_WrongArity(ctx);
    }

    CuckooFilter *cf;
    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ | VALKEYMODULE_WRITE);
    int status = cfGetFilter(key, &cf);

    // Pos, blob
    long long pos;
    if (ValkeyModule_StringToLongLong(argv[2], &pos) != VALKEYMODULE_OK || pos == 0) {
        return ValkeyModule_ReplyWithError(ctx, "Invalid position");
    }
    size_t bloblen;
    const char *blob = ValkeyModule_StringPtrLen(argv[3], &bloblen);

    if (pos == 1) {
        if (status != SB_EMPTY) {
            return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
        } else if (bloblen != sizeof(CFHeader)) {
            return ValkeyModule_ReplyWithError(ctx, "Invalid header");
        }

        cf = CFHeader_Load((CFHeader *)blob);
        if (cf == NULL) {
            return ValkeyModule_ReplyWithError(ctx, "Couldn't create filter!");
        }
        ValkeyModule_ModuleTypeSetValue(key, CFType, cf);
        return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
    }

    if (status != SB_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    if (CF_LoadEncodedChunk(cf, pos, blob, bloblen) != VALKEYMODULE_OK) {
        return ValkeyModule_ReplyWithError(ctx, "Couldn't load chunk!");
    }
    return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
}

static int CFInfo_ValkeyCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    ValkeyModule_AutoMemory(ctx);
    if (argc != 2) {
        return ValkeyModule_WrongArity(ctx);
    }

    CuckooFilter *cf;
    ValkeyModuleKey *key = ValkeyModule_OpenKey(ctx, argv[1], VALKEYMODULE_READ);
    int status = cfGetFilter(key, &cf);
    if (status != VALKEYMODULE_OK) {
        return ValkeyModule_ReplyWithError(ctx, statusStrerror(status));
    }

    ValkeyModuleString *resp = ValkeyModule_CreateStringPrintf(
        ctx, "bktsize:%u buckets:%lu items:%lu deletes:%lu filters:%lu", CUCKOO_BKTSIZE,
        cf->numBuckets, cf->numItems, cf->numDeletes, cf->numFilters);
    return ValkeyModule_ReplyWithString(ctx, resp);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
/// Datatype Functions                                                       ///
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#define BF_ENCODING_VERSION 3
#define BF_MIN_OPTIONS_ENC 2

static void BFRdbSave(ValkeyModuleIO *io, void *obj) {
    // Save the setting!
    SBChain *sb = obj;

    ValkeyModule_SaveUnsigned(io, sb->size);
    ValkeyModule_SaveUnsigned(io, sb->nfilters);
    ValkeyModule_SaveUnsigned(io, sb->options);

    for (size_t ii = 0; ii < sb->nfilters; ++ii) {
        const SBLink *lb = sb->filters + ii;
        const struct bloom *bm = &lb->inner;

        ValkeyModule_SaveUnsigned(io, bm->entries);
        ValkeyModule_SaveDouble(io, bm->error);
        ValkeyModule_SaveUnsigned(io, bm->hashes);
        ValkeyModule_SaveDouble(io, bm->bpe);
        ValkeyModule_SaveUnsigned(io, bm->bits);
        ValkeyModule_SaveUnsigned(io, bm->n2);
        ValkeyModule_SaveStringBuffer(io, (const char *)bm->bf, bm->bytes);

        // Save the number of actual entries stored thus far.
        ValkeyModule_SaveUnsigned(io, lb->size);
    }
}

static void *BFRdbLoad(ValkeyModuleIO *io, int encver) {
    if (encver > BF_ENCODING_VERSION) {
        return NULL;
    }

    // Load our modules
    SBChain *sb = ValkeyModule_Calloc(1, sizeof(*sb));
    sb->size = ValkeyModule_LoadUnsigned(io);
    sb->nfilters = ValkeyModule_LoadUnsigned(io);
    if (encver >= BF_MIN_OPTIONS_ENC) {
        sb->options = ValkeyModule_LoadUnsigned(io);
    }

    // Sanity:
    assert(sb->nfilters < 1000);
    sb->filters = ValkeyModule_Calloc(sb->nfilters, sizeof(*sb->filters));

    for (size_t ii = 0; ii < sb->nfilters; ++ii) {
        SBLink *lb = sb->filters + ii;
        struct bloom *bm = &lb->inner;

        bm->entries = ValkeyModule_LoadUnsigned(io);
        bm->error = ValkeyModule_LoadDouble(io);
        bm->hashes = ValkeyModule_LoadUnsigned(io);
        bm->bpe = ValkeyModule_LoadDouble(io);
        if (encver == 0) {
            bm->bits = (double)bm->entries * bm->bpe;
        } else {
            bm->bits = ValkeyModule_LoadUnsigned(io);
            bm->n2 = ValkeyModule_LoadUnsigned(io);
        }
        if (sb->options & BLOOM_OPT_FORCE64) {
            bm->force64 = 1;
        }
        size_t sztmp;
        bm->bf = (unsigned char *)ValkeyModule_LoadStringBuffer(io, &sztmp);
        bm->bytes = sztmp;
        lb->size = ValkeyModule_LoadUnsigned(io);
    }

    return sb;
}

static void BFAofRewrite(ValkeyModuleIO *aof, ValkeyModuleString *key, void *value) {
    SBChain *sb = value;
    size_t len;
    char *hdr = SBChain_GetEncodedHeader(sb, &len);
    ValkeyModule_EmitAOF(aof, "BF.LOADCHUNK", "slb", key, 0, hdr, len);
    SB_FreeEncodedHeader(hdr);

    long long iter = SB_CHUNKITER_INIT;
    const char *chunk;
    while ((chunk = SBChain_GetEncodedChunk(sb, &iter, &len, MAX_SCANDUMP_SIZE)) != NULL) {
        ValkeyModule_EmitAOF(aof, "BF.LOADCHUNK", "slb", key, iter, chunk, len);
    }
}

static void BFFree(void *value) { SBChain_Free(value); }

static size_t BFMemUsage(const void *value) {
    const SBChain *sb = value;
    size_t rv = sizeof(*sb);
    for (size_t ii = 0; ii < sb->nfilters; ++ii) {
        rv += sizeof(*sb->filters);
        rv += sb->filters[ii].inner.bytes;
    }
    return rv;
}

static void CFFree(void *value) {
    CuckooFilter_Free(value);
    ValkeyModule_Free(value);
}

static void CFRdbSave(ValkeyModuleIO *io, void *obj) {
    CuckooFilter *cf = obj;
    ValkeyModule_SaveUnsigned(io, cf->numFilters);
    ValkeyModule_SaveUnsigned(io, cf->numBuckets);
    ValkeyModule_SaveUnsigned(io, cf->numItems);
    for (size_t ii = 0; ii < cf->numFilters; ++ii) {
        ValkeyModule_SaveStringBuffer(io, (char *)cf->filters[ii],
                                     cf->numBuckets * sizeof(*cf->filters[ii]));
    }
}

static void *CFRdbLoad(ValkeyModuleIO *io, int encver) {
    if (encver > BF_ENCODING_VERSION) {
        return NULL;
    }

    CuckooFilter *cf = ValkeyModule_Calloc(1, sizeof(*cf));
    cf->numFilters = ValkeyModule_LoadUnsigned(io);
    cf->numBuckets = ValkeyModule_LoadUnsigned(io);
    cf->numItems = ValkeyModule_LoadUnsigned(io);
    cf->filters = ValkeyModule_Calloc(cf->numFilters, sizeof(*cf->filters));
    for (size_t ii = 0; ii < cf->numFilters; ++ii) {
        size_t lenDummy = 0;
        cf->filters[ii] = (CuckooBucket *)ValkeyModule_LoadStringBuffer(io, &lenDummy);
        assert(cf->filters[ii] != NULL && lenDummy == sizeof(CuckooBucket) * cf->numBuckets);
    }
    return cf;
}

static size_t CFMemUsage(const void *value) {
    const CuckooFilter *cf = value;
    return sizeof(*cf) + sizeof(CuckooBucket) * cf->numBuckets * cf->numFilters;
}

static void CFAofRewrite(ValkeyModuleIO *aof, ValkeyModuleString *key, void *obj) {
    CuckooFilter *cf = obj;
    const char *chunk;
    size_t nchunk;
    CFHeader header;
    fillCFHeader(&header, cf);

    long long pos = 1;
    ValkeyModule_EmitAOF(aof, "CF.LOADCHUNK", "slb", key, pos, (const char *)&header, sizeof header);
    while ((chunk = CF_GetEncodedChunk(cf, &pos, &nchunk, MAX_SCANDUMP_SIZE))) {
        ValkeyModule_EmitAOF(aof, "CF.LOADCHUNK", "slb", key, pos, chunk, nchunk);
    }
}

static int rsStrcasecmp(const ValkeyModuleString *rs1, const char *s2) {
    size_t n1 = strlen(s2);
    size_t n2;
    const char *s1 = ValkeyModule_StringPtrLen(rs1, &n2);
    if (n1 != n2) {
        return -1;
    }
    return strncasecmp(s1, s2, n1);
}

#define BAIL(s, ...)                                                                               \
    do {                                                                                           \
        ValkeyModule_Log(ctx, "warning", s, ##__VA_ARGS__);                                         \
        return VALKEYMODULE_ERR;                                                                    \
    } while (0);

int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (ValkeyModule_Init(ctx, "bf", VALKEYBLOOM_MODULE_VERSION, VALKEYMODULE_APIVER_1) !=
        VALKEYMODULE_OK) {
        return VALKEYMODULE_ERR;
    }

    if (argc == 1) {
        ValkeyModule_Log(ctx, "notice", "Found empty string. Assuming ramp-packer validation");
        // Hack for ramp-packer which gives us an empty string.
        size_t tmp;
        ValkeyModule_StringPtrLen(argv[0], &tmp);
        if (tmp == 0) {
            argc = 0;
        }
    }

    if (argc % 2) {
        BAIL("Invalid number of arguments passed");
    }

    for (int ii = 0; ii < argc; ii += 2) {
        if (!rsStrcasecmp(argv[ii], "initial_size")) {
            long long v;
            if (ValkeyModule_StringToLongLong(argv[ii + 1], &v) == VALKEYMODULE_ERR) {
                BAIL("Invalid argument for 'INITIAL_SIZE'");
            }
            if (v > 0) {
                BFDefaultInitCapacity = v;
            } else {
                BAIL("INITIAL_SIZE must be > 0");
            }
        } else if (!rsStrcasecmp(argv[ii], "error_rate")) {
            double d;
            if (ValkeyModule_StringToDouble(argv[ii + 1], &d) == VALKEYMODULE_ERR) {
                BAIL("Invalid argument for 'ERROR_RATE'");
            } else if (d <= 0) {
                BAIL("ERROR_RATE must be > 0");
            } else {
                BFDefaultErrorRate = d;
            }
        } else if (!rsStrcasecmp(argv[ii], "cf_max_expansions")) {
            long long l;
            if (ValkeyModule_StringToLongLong(argv[ii + 1], &l) == VALKEYMODULE_ERR || l == 0) {
                BAIL("Invalid argument for 'CF_MAX_EXPANSIONS'");
            }
            CFMaxExpansions = l;
        } else {
            BAIL("Unrecognized option");
        }
    }

#define CREATE_CMD(name, tgt, attr)                                                                \
    do {                                                                                           \
        if (ValkeyModule_CreateCommand(ctx, name, tgt, attr, 1, 1, 1) != VALKEYMODULE_OK) {          \
            return VALKEYMODULE_ERR;                                                                \
        }                                                                                          \
    } while (0)
#define CREATE_WRCMD(name, tgt) CREATE_CMD(name, tgt, "write deny-oom")
#define CREATE_ROCMD(name, tgt) CREATE_CMD(name, tgt, "readonly fast")

    CREATE_WRCMD("BF.RESERVE", BFReserve_ValkeyCommand);
    CREATE_WRCMD("BF.ADD", BFAdd_ValkeyCommand);
    CREATE_WRCMD("BF.MADD", BFAdd_ValkeyCommand);
    CREATE_WRCMD("BF.INSERT", BFInsert_ValkeyCommand);
    CREATE_ROCMD("BF.EXISTS", BFCheck_ValkeyCommand);
    CREATE_ROCMD("BF.MEXISTS", BFCheck_ValkeyCommand);

    // Bloom - Debug
    CREATE_ROCMD("BF.DEBUG", BFInfo_ValkeyCommand);
    // Bloom - AOF
    CREATE_ROCMD("BF.SCANDUMP", BFScanDump_ValkeyCommand);
    CREATE_WRCMD("BF.LOADCHUNK", BFLoadChunk_ValkeyCommand);

    // Cuckoo Filter commands
    CREATE_WRCMD("CF.RESERVE", CFReserve_ValkeyCommand);
    CREATE_WRCMD("CF.ADD", CFAdd_ValkeyCommand);
    CREATE_WRCMD("CF.ADDNX", CFAdd_ValkeyCommand);
    CREATE_WRCMD("CF.INSERT", CFInsert_ValkeyCommand);
    CREATE_WRCMD("CF.INSERTNX", CFInsert_ValkeyCommand);
    CREATE_ROCMD("CF.EXISTS", CFCheck_ValkeyCommand);
    CREATE_ROCMD("CF.MEXISTS", CFCheck_ValkeyCommand);
    CREATE_ROCMD("CF.COUNT", CFCheck_ValkeyCommand);

    // Technically a write command, but doesn't change memory profile
    CREATE_CMD("CF.DEL", CFDel_ValkeyCommand, "write fast");

    // AOF:
    CREATE_ROCMD("CF.SCANDUMP", CFScanDump_ValkeyCommand);
    CREATE_WRCMD("CF.LOADCHUNK", CFLoadChunk_ValkeyCommand);

    CREATE_ROCMD("CF.DEBUG", CFInfo_ValkeyCommand);

    static ValkeyModuleTypeMethods typeprocs = {.version = VALKEYMODULE_TYPE_METHOD_VERSION,
                                               .rdb_load = BFRdbLoad,
                                               .rdb_save = BFRdbSave,
                                               .aof_rewrite = BFAofRewrite,
                                               .free = BFFree,
                                               .mem_usage = BFMemUsage};
    BFType = ValkeyModule_CreateDataType(ctx, "MBbloom--", BF_ENCODING_VERSION, &typeprocs);
    if (BFType == NULL) {
        return VALKEYMODULE_ERR;
    }

    static ValkeyModuleTypeMethods cfTypeProcs = {.version = VALKEYMODULE_TYPE_METHOD_VERSION,
                                                 .rdb_load = CFRdbLoad,
                                                 .rdb_save = CFRdbSave,
                                                 .aof_rewrite = CFAofRewrite,
                                                 .free = CFFree,
                                                 .mem_usage = CFMemUsage};
    CFType = ValkeyModule_CreateDataType(ctx, "MBbloomCF", BF_ENCODING_VERSION, &cfTypeProcs);
    if (CFType == NULL) {
        return VALKEYMODULE_ERR;
    }
    return VALKEYMODULE_OK;
}
