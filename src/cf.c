#include "valkeymodule.h"
#define CUCKOO_MALLOC ValkeyModule_Alloc
#define CUCKOO_CALLOC ValkeyModule_Calloc
#define CUCKOO_REALLOC ValkeyModule_Realloc
#define CUCKOO_FREE ValkeyModule_Free
#include "cuckoo.c"
#include "cf.h"

// Get the bucket corresponding to the given position. 'offset' is modified to be the
// actual position (beginning of bucket) where `pos` is mapped to, with respect to
// the current filter. The filter itself is not returned directly (but can be inferred)
// via `offset`
static uint8_t *getBucketPos(const CuckooFilter *cf, long long pos, size_t *offset) {
    // Normalize the pos pointer to the beginning of the filter
    pos--;
    *offset = pos % cf->numBuckets;
    // Get the actual filter index.
    size_t filterIx = (pos - (pos % cf->numBuckets)) / cf->numBuckets;

    if (filterIx >= cf->numFilters) {
        // Last position
        return NULL;
    }

    if (*offset + 1 == cf->numBuckets) {
        *offset = 0;
        if (++filterIx == cf->numFilters) {
            return NULL;
        }
    }
    return cf->filters[filterIx][*offset];
}

const char *CF_GetEncodedChunk(const CuckooFilter *cf, long long *pos, size_t *buflen,
                               size_t bytelimit) {
    size_t offset;
    uint8_t *bucket = getBucketPos(cf, *pos, &offset);
    if (!bucket) {
        return NULL;
    }
    size_t chunksz = cf->numBuckets - offset;
    size_t max_buckets = (bytelimit / CUCKOO_BKTSIZE);
    if (chunksz > max_buckets) {
        chunksz = max_buckets;
    }
    *pos += chunksz;
    *buflen = chunksz * CUCKOO_BKTSIZE;
    return (const char *)bucket;
}

int CF_LoadEncodedChunk(const CuckooFilter *cf, long long pos, const char *data, size_t datalen) {
    if (datalen == 0 || datalen % CUCKOO_BKTSIZE != 0) {
        // printf("problem with datalen!\n");
        return VALKEYMODULE_ERR;
    }

    size_t nbuckets = datalen / CUCKOO_BKTSIZE;
    if (nbuckets > pos) {
        // printf("nbuckets>pos. pos=%lu. nbuckets=%lu\n", nbuckets, pos);
        return VALKEYMODULE_ERR;
    }

    pos -= nbuckets;

    size_t offset;
    uint8_t *bucketpos = getBucketPos(cf, pos, &offset);
    if (bucketpos == NULL) {
        // printf("bucketpos=NULL\n");
        return VALKEYMODULE_ERR;
    }

    // printf("OFFSET: %lu\n", offset);

    if (offset + nbuckets > cf->numBuckets) {
        // printf("offset+nbuckets > cf->numBuckets. offset=%lu, nbuckets=%lu, numBuckets=%lu\n",
        //        offset, nbuckets, cf->numBuckets);
        return VALKEYMODULE_ERR;
    }

    memcpy(bucketpos, data, datalen);
    return VALKEYMODULE_OK;
}

CuckooFilter *CFHeader_Load(const CFHeader *header) {
    CuckooFilter *filter = ValkeyModule_Calloc(1, sizeof(*filter));
    filter->numBuckets = header->numBuckets;
    filter->numFilters = header->numFilters;
    filter->numItems = header->numItems;
    filter->numDeletes = header->numDeletes;
    filter->filters = ValkeyModule_Alloc(sizeof(*filter->filters) * header->numFilters);
    for (size_t ii = 0; ii < filter->numFilters; ++ii) {
        filter->filters[ii] = ValkeyModule_Calloc(filter->numBuckets, sizeof(CuckooBucket));
    }
    return filter;
}
