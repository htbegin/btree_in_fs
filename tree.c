#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "balloc.h"

/* fixed-length key and data */
typedef struct bkey_t {
    uint64_t offset;
} bkey_t;

typedef struct bdata_t {
    uint64_t start;
} bdata_t;

typedef struct node_header_t {
    uint32_t magic;
    uint32_t level;
    uint32_t cnt;
}node_header_t;

typedef struct leaf_header_t {
    uint32_t magic;
    uint32_t cnt;
    uint32_t left;
    uint32_t right;
} leaf_header_t;

typedef struct btree_t {
    ballocator_t *balloc;
    node_header_t *root;
} btree_t;

int btree_new(ballocator_t *balloc, btree_t **btree)
{
    return 0;
}

int btree_search(btree_t *tree, const bkey_t *key, bdata_t *data)
{
    return 0;
}

int btree_insert(btree_t *tree, const bkey_t *key, const bdata_t *data)
{
    return 0;
}

int btree_delete(btree_t *tree, const bkey_t *key, bdata_t *data)
{
    return 0;
}

void btree_dump(btree_t *btree)
{
}

int main(int argc, char **argv)
{
    const int cnt = 0;
    ballocator_t *balloc;
    btree_t *btree;
    int i;
    int ret;
    bkey_t key;
    bdata_t data;

    balloc_init("/tmp/tree", &balloc);

    btree_new(balloc, &btree);

    for (i = 0; i < cnt; i++) {
        key.offset = i;
        data.start = i;

        ret = btree_insert(btree, &key, &data);
        assert(ret == 0);
    }

    for (i = cnt - 1; i >= 0; i--) {
        key.offset = i;
        ret = btree_search(btree, &key, &data);
        assert(ret == 0);
        assert(data.start == i);
    }

    btree_dump(btree);

    for (i = 0; i < cnt; i++) {
        ret = btree_delete(btree, &key, &data);
        assert(ret == 0);
        assert(data.start == i);
    }

    balloc_exit(balloc);

    return 0;
}
