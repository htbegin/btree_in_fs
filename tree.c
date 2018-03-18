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

typedef struct bndata_t {
    uint32_t blkno;
}bndata_t;

#define BTREE_NODE_MAGIC 0xABCD5678
#define BTREE_LEAF_MAGIC 0xEF014567

#define BTREE_NODE_FULL_CNT 399
#define BTREE_NODE_HALF_CNT 169
/*
 * key cnt: [Tn - 1, 2Tn - 1], pointer cnt: [Tn, 2Tn]
 * 2Tn - 1 = 339, Tn = 170
 * 4096 - (339 * (8 + 4) + 4) = 4096 - 4072 = 24
 * cnt [169, 339]
 */
typedef struct node_header_t {
    uint32_t magic;
    uint32_t blkno;
    uint32_t level;
    uint32_t cnt;
    uint8_t pad[8];
}node_header_t;

#define BTREE_LEAF_FULL_CNT 254
#define BTREE_LEAF_HALF_CNT 127

/*
 * key cnt & value cnt: [Tl, 2Tl]
 * 2Tleaf = 254, Tleaf = 127
 * 4096 - (254 * (8 + 8)) = 4096 - 4064 = 32
 * cnt [127, 254]
 */
typedef struct leaf_header_t {
    uint32_t magic;
    uint32_t blkno;
    uint32_t cnt;
    uint32_t left;
    uint32_t right;
    uint8_t pad[12];
} leaf_header_t;

typedef struct btree_t {
    ballocator_t *balloc;
    int level;
    void *root;
} btree_t;

static void btree_init_leaf(leaf_header_t *leaf, uint32_t blkno)
{
    memset(leaf, 0, sizeof(*leaf));
    leaf->magic = BTREE_LEAF_MAGIC;
    leaf->blkno = blkno;
}

static void btree_init_node(node_header_t *node, uint32_t blkno)
{
    memset(node, 0, sizeof(*node));
    node->magic = BTREE_NODE_MAGIC;
    node->blkno = blkno;
}

static inline bool btree_node_is_full(node_header_t *node)
{
    return (node->cnt == BTREE_NODE_FULL_CNT);
}

static inline bool btree_leaf_is_full(leaf_header_t *leaf)
{
    return (leaf->cnt == BTREE_LEAF_FULL_CNT);
}

static inline bool btree_nl_is_full(int level, void *root)
{
    if (level)
        return btree_node_is_full(root);
    else
        return btree_leaf_is_full(root);
}

static inline uint32_t btree_root_blkno(btree_t *btree)
{
    void *root = btree->root;
    uint32_t blkno;

    if (btree->level) {
        node_header_t *node = root;

        blkno = root->blkno;
    } else {
        leaf_header_t *leaf = root;

        blkno = leaf->blkno;
    }

    return blkno;
}

static void *btree_leaf_key_ptr(leaf_header_t *leaf, int idx)
{
    return ((char *)&leaf[1] + idx * sizeof(bkey_t));
}

static void *btree_leaf_node_ptr(leaf_header_t *leaf, int idx)
{
    return ((char *)&leaf[1] + BTREE_LEAF_FULL_CNT * sizeof(bkey_t) +
            idx * sizeof(bdata_t));
}

static void *btree_node_key_ptr(node_header_t *node, int idx)
{
    return ((char *)&node[1] + idx * sizeof(bkey_t));
}

static void *btree_node_node_ptr(node_header_t *node, int idx)
{
    return ((char *)&node[1] + BTREE_NODE_FULL_CNT * sizeof(bkey_t) +
            idx * sizeof(bndata_t));
}

static inline int btree_cmp_key(const bkey_t *left, const bkey_t *right)
{
    return ((left->offset < right->offset) ? -1 :
             ((left->offset > right->offset) ? 1 : 0));
}

int btree_new(ballocator_t *balloc, btree_t **btree)
{
    btree_t *new_btree;
    uint32_t blkno;
    void *raw;
    leaf_header_t *root;

    new_btree = malloc(sizeof(*new_btree));
    assert(new_btree);

    balloc_alloc_read(balloc, &blkno, &raw);
    root = raw;

    btree_init_leaf(root, blkno);

    new_btree->balloc = balloc;
    new_btree->level = 0;
    new_btree->root = root;

    *btree = new_btree;

    return 0;
}

int btree_search(btree_t *btree, const bkey_t *key, bdata_t *data)
{
    return 0;
}

/*
 * block pointed by btree_node_data_ptr(node, idx) is full, and it
 * needs split.
 */
int btree_split_child(btree_t *btree, node_header_t *node, int idx)
{
    uint32_t right_blkno;
    uint32_t left_blkno;
    void *right_raw;
    void *left_raw;
    void *from;
    void *to;
    size_t len;
    bkey_t *moved_key;
    bkey_t *new_key;
    bndata_t *new_ndata;

    balloc_alloc_read(btree->balloc, &right_blkno, &right_raw);
    balloc_read(btree->balloc, left_blkno, &left_raw);

    if (node->level == 1) {
        leaf_header_t *left = left_raw;
        leaf_header_t *right = right_raw;

        btree_init_leaf(right, right_blkno);
        right->cnt = BTREE_LEAF_HALF_CNT;

        to = btree_leaf_key_ptr(right, 0);
        from = btree_leaf_key_ptr(left, BTREE_LEAF_HALF_CNT);
        len = sizeof(bkey_t) * right->cnt;
        memcpy(to, from, len);

        to = btree_leaf_data_ptr(right, 0);
        from = btree_leaf_data_ptr(left, BTREE_LEAF_HALF_CNT);
        len = sizeof(bdata_t) * right->cnt;
        memcpy(to, from, len);

        left->cnt = BTREE_LEAF_HALF_CNT;

        moved_key = btree_leaf_key_ptr(left, BTREE_LEAF_HALF_CNT);

        right->right = left->right;
        if (right->right) {
            leaf_header_t *next;

            balloc_read(btree->balloc, right->right, &(void *)next);
            next->left = right_blkno;
        }
        right->left = left_blkno;
        left->right = right_blkno;
    } else {
        node_header_t *left = left_raw;
        node_header_t *right = right_raw;

        btree_init_node(right, right_blkno);
        right->cnt = BTREE_NODE_HALF_CNT;

        to = btree_node_key_ptr(right, 0);
        from = btree_node_key_ptr(left, BTREE_NODE_HALF_CNT + 1);
        len = sizeof(bkey_t) * right->cnt;
        memcpy(to, from, len);

        to = btree_node_data_ptr(right, 0);
        from = btree_node_data_ptr(left, BTREE_NODE_HALF_CNT + 1);
        len = sizeof(bndata_t) * right->cnt;
        memcpy(to, from, len);

        left->cnt = BTREE_NODE_HALF_CNT;

        moved_key = btree_node_key_ptr(left, BTREE_NODE_HALF_CNT);
    }

    to = btree_node_key_ptr(node, idx + 1);
    from = btree_node_key_ptr(node, idx);
    len = sizeof(bkey_t) * (node->cnt - idx);
    memmove(to, from, len);

    new_key = btree_node_key_ptr(node, idx);
    *new_key = *moved_key;

    to = btree_node_data_ptr(node, idx + 2);
    from = btree_node_data_ptr(node, idx + 1);
    len = sizeof(bndata_t) * (node->cnt- idx);
    memmove(to, from, len);

    new_ndata = btree_node_data_ptr(node, idx + 1);
    new_ndata->blkno = right_blkno;

    node->cnt += 1;

    return 0;
}

int btree_insert_leaf_nonfull(btree_t *btree, leaf_header_t *leaf,
        const bkey_t *key, const bdata_t *data)
{
    unsigned int i = leaf->cnt;
    bkey_t *leaf_key = btree_leaf_key_ptr(leaf, i - 1);
    int ret;

    while (i >= 1) {
        ret = btree_cmp_key(key, leaf_key);
        assert(ret != 0);
        if (ret > 0)
            break;
        
        *(leaf_key + 1) = *leaf_key;
        i--;
        leaf_key--;
    }

    *btree_leaf_key_ptr(leaf, i) = *key;
    *btree_leaf_data_ptr(leaf, i) = *data;

    leaf->cnt += 1;

    return 0;
}

int btree_insert_node_nonfull(btree_t *btree, node_header_t *node,
        const bkey_t *key, const bdata_t *data)
{
    unsigned int i = node->cnt;
    bkey_t *leaf_key = btree_node_key_ptr(node, i - 1);
    int ret;
    bndata_t *ndata;
    void *raw;

    while (i >= 1) {
        ret = btree_cmp_key(key, leaf_key);
        /* assert(ret != 0) */
        if (ret >= 0)
            break;

        leaf_key--;
        i--;
    }

    ndata = btree_node_data_ptr(node, i);
    balloc_read(btree->balloc, ndata->blkno, &raw);

    if (btree_nl_is_full(node->level - 1, raw)) {
        btree_split_child(btree, node, i);

        ret = btree_cmp_key(key, btree_node_key_ptr(node, i));
        if (ret > 0) {
            ndata = btree_node_data_ptr(node, i + 1);
            balloc_read(btree->balloc, ndata->blkno, &raw);
        }
    }

    if (node->level != 1)
        btree_insert_node_nonfull(btree, raw, data, key);
    else
        btree_insert_leaf_nonfull(btree, raw, data, key);

    return 0;
}

int btree_insert(btree_t *btree, const bkey_t *key, const bdata_t *data)
{
    int level = btree->level;
    void *root = btree->root;

    if (btree_nl_is_full(level, root)) {
        uint32_t blkno;
        node_header_t *node;
        bndata_t *data;

        balloc_alloc_read(btree->balloc, &blkno, &(void *)node);

        btree_init_node(node, blkno);
        node->level = btree->level + 1;

        data = btree_node_data_ptr(node, 0);
        data->blkno = btree_root_blkno(btree);

        btree_split_child(btree, node, 0);

        btree->root = node;
        btree->level = node->level;

        btree_insert_node_nonfull(btree, node, key, data);
    } else {
        void *root = btree->root;

        if (btree->level)
            btree_insert_node_nonfull(btree, root, key, data);
        else
            btree_insert_leaf_nonfull(btree, root, key, data);
    }

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
