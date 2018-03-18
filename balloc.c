#include <inttypes.h>
#include <assert.h>
#include "balloc.h"

struct ballocator {
    uint32_t total;
    uint32_t next;
};

/*
 * 1. the block size is 4KB
 * 2. a fixed-size file (64MB) is used for block management
 */
int balloc_init(const char *path, ballocator_t **balloc)
{
    /* stat */
    /* mmap */
    /* 
    return 0;
}

int balloc_alloc(ballocator_t *balloc, uint32_t *blkno)
{
    /* 
    return 0;
}

int balloc_read(ballocator_t *balloc, uint32_t *blkno, void **raw)
{
    return 0;
}

int balloc_free(ballocator_t *balloc, uint32_t blkno)
{
    return 0;
}

void balloc_exit(ballocator_t *balloc)
{
}

