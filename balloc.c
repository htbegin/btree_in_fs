#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#include "balloc.h"

#define BA_BLK_SHIFT 12
#define BA_BLK_SIZE (1 << BA_BLK_SHIFT)
#define BA_BLK_MASK (~(BA_BLK_SIZE - 1))

#define BA_BM_SHIFT 6
#define BA_BM_UNIT (1 << BA_BM_SHIFT)
#define BA_BM_MASK (~(BA_BM_UNIT - 1))

typedef struct ballocator {
    void *base;
    uint64_t *bitmap;
    uint32_t total_size;
    uint32_t bitmap_size;
    uint32_t total_blk_cnt;
    uint32_t rsv_blk_cnt;
    uint32_t free_blk_cnt;
    uint32_t next_blk;
} ballocator;

int ba_blk_allocated(uint64_t *bitmap, uint32_t blkno)
{
    int idx = (blkno >> BA_BM_SHIFT);
    int bit = (blkno & ~BA_BM_MASK);

    return !!(bitmap[idx] & (1ULL << bit));
}

void ba_allocate_blk(uint64_t *bitmap, uint32_t blkno)
{
    int idx = (blkno >> BA_BM_SHIFT);
    int bit = (blkno & ~BA_BM_MASK);

    bitmap[idx] |= (1ULL << bit);
}

int balloc_init(const char *path, ballocator_t **balloc)
{
    ballocator_t *nballoc;
    int fd;
    struct stat info;
    int err;
    void *addr;
    int i;

    nballoc = malloc(sizeof(*nballoc));

    fd = open(path, O_RDWR);
    assert(fd >= 0);

    err = fstat(fd, &info);
    assert(!err);

    addr = mmap(NULL, info.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(addr != MAP_FAILED);

    close(fd);

    nballoc->total_size = info.st_size;
    nballoc->bitmap_size = (((nballoc->total_size >> BA_BLK_SHIFT) +
                BA_BM_UNIT - 1) & BA_BM_MASK) / 8;
    nballoc->base = addr;
    nballoc->bitmap = addr;

    nballoc->total_blk_cnt = nballoc->total_size  >> BA_BLK_SHIFT;
    nballoc->rsv_blk_cnt = (nballoc->bitmap_size + BA_BLK_SIZE - 1) >>
        BA_BLK_SHIFT;
    nballoc->free_blk_cnt = nballoc->total_blk_cnt - nballoc->rsv_blk_cnt;
    nballoc->next_blk = nballoc->rsv_blk_cnt;

    memset(nballoc->bitmap, 0, nballoc->bitmap_size);
    for (i = 0; i < nballoc->rsv_blk_cnt; i++)
        ba_allocate_blk(nballoc->bitmap, i);

    *balloc = nballoc;

    return 0;
}

int balloc_alloc_read(ballocator_t *balloc, uint32_t *blkno, void **raw)
{
    if (balloc->free_blk_cnt == 0) {
        printf("no free blk\n");
        assert(0);
        return -1;
    }

    if (ba_blk_allocated(balloc->bitmap, balloc->next_blk)) {
        assert(0);
        return -1;
    }

    *blkno = balloc->next_blk;
    *raw = ((char *)balloc->base + (balloc->next_blk << BA_BLK_SHIFT));

    ba_allocate_blk(balloc->bitmap, balloc->next_blk);
    balloc->next_blk++;
    balloc->free_blk_cnt--;

    return 0;
}

int balloc_read(ballocator_t *balloc, uint32_t blkno, void **raw)
{
    if (blkno < balloc->rsv_blk_cnt || blkno >= balloc->total_blk_cnt) {
        printf("blkno %u (rsv %u, total %u)\n", blkno,
                balloc->rsv_blk_cnt,
                balloc->total_blk_cnt);
        assert(0);
        return -1;
    }

    *raw = ((char *)balloc->base + (blkno << BA_BLK_SHIFT));

    return 0;
}

int balloc_free(ballocator_t *balloc, uint32_t blkno)
{
    return 0;
}

void balloc_exit(ballocator_t *balloc)
{
}

