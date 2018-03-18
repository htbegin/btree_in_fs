
#ifndef __BALLOC_H__
#define __BALLOC_H__

typedef struct ballocator ballocator_t;
/*
 * 1. the block size is 4KB
 * 2. a fixed-size file (64MB) is used for block management
 */
int balloc_init(const char *path, ballocator_t **balloc);
int balloc_alloc(ballocator_t *balloc, uint32_t *blkno);
int balloc_read(ballocator_t *balloc, uint32_t *blkno, void **raw);
int balloc_free(ballocator_t *balloc, uint32_t blkno);
void balloc_exit(ballocator_t *balloc);

#endif

