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

#define BTREE_NODE_FULL_CNT 339
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

static int verbose = 0;

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

static inline int btree_node_is_full(node_header_t *node)
{
    return (node->cnt == BTREE_NODE_FULL_CNT);
}

static inline int btree_leaf_is_full(leaf_header_t *leaf)
{
    return (leaf->cnt == BTREE_LEAF_FULL_CNT);
}

static inline int btree_nl_is_full(int level, void *root)
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

        blkno = node->blkno;
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

static void *btree_leaf_data_ptr(leaf_header_t *leaf, int idx)
{
    return ((char *)&leaf[1] + BTREE_LEAF_FULL_CNT * sizeof(bkey_t) +
            idx * sizeof(bdata_t));
}

static void *btree_node_key_ptr(node_header_t *node, int idx)
{
    return ((char *)&node[1] + idx * sizeof(bkey_t));
}

static void *btree_node_data_ptr(node_header_t *node, int idx)
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
    btree_t *nbtree;
    uint32_t blkno;
    void *raw;
    leaf_header_t *root;

    nbtree = malloc(sizeof(*nbtree));
    assert(nbtree);

    balloc_alloc_read(balloc, &blkno, &raw);
    root = raw;

    btree_init_leaf(root, blkno);

    nbtree->balloc = balloc;
    nbtree->level = 0;
    nbtree->root = root;

    *btree = nbtree;

    return 0;
}

static int btree_search_leaf(btree_t *btree, leaf_header_t *leaf, const bkey_t *key, bdata_t *data)
{
    int ret = 0;
    unsigned int i;
    bkey_t *leaf_key = btree_leaf_key_ptr(leaf, 0);
    int cmp = 1;

    for (i = 0; i < leaf->cnt; i++, leaf_key++) {
        cmp = btree_cmp_key(key, leaf_key);
        if (cmp <= 0)
            break;
    }

    if (cmp == 0)
        *data = *(bdata_t *)btree_leaf_data_ptr(leaf, i);
    else
        ret = -1;

    return ret;
}

static int btree_search_node(btree_t *btree, node_header_t *node, const bkey_t *key, bdata_t *data)
{
    unsigned int i;
    node_header_t *cur;
    bkey_t *nkey;
    bndata_t *ndata;
    void *raw;
    leaf_header_t *leaf;

    cur = node;
    while (1) {
        i = 0;
        nkey = btree_node_key_ptr(cur, 0);
        while (i < cur->cnt) {
            if (btree_cmp_key(key, nkey) <= 0)
                break;
            i++;
            nkey++;
        }

        ndata = btree_node_data_ptr(cur, i);
        balloc_read(btree->balloc, ndata->blkno, &raw);
        if (cur->level != 1) {
            cur = raw;
        } else {
            leaf = raw;
            break;
        }
    }

    return btree_search_leaf(btree, leaf, key, data);
}

int btree_search(btree_t *btree, const bkey_t *key, bdata_t *data)
{
    int ret;
    void *root = btree->root;

    if (btree->level != 0)
        ret = btree_search_node(btree, root, key, data);
    else
        ret = btree_search_leaf(btree, root, key, data);

    return ret;
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

    left_blkno = ((bndata_t *)btree_node_data_ptr(node, idx))->blkno;
    balloc_read(btree->balloc, left_blkno, &left_raw);
    balloc_alloc_read(btree->balloc, &right_blkno, &right_raw);

    if (node->level == 1) {
        leaf_header_t *left = left_raw;
        leaf_header_t *right = right_raw;

        btree_init_leaf(right, right_blkno);
        right->cnt = BTREE_LEAF_HALF_CNT;

        /* [0, half - 1], half - 1, [half, 2 * half - 1] */
        to = btree_leaf_key_ptr(right, 0);
        from = btree_leaf_key_ptr(left, BTREE_LEAF_HALF_CNT);
        len = sizeof(bkey_t) * right->cnt;
        memcpy(to, from, len);
        memset(from, 0, len);

        /* [0, half - 1], [half, 2 * half - 1] */
        to = btree_leaf_data_ptr(right, 0);
        from = btree_leaf_data_ptr(left, BTREE_LEAF_HALF_CNT);
        len = sizeof(bdata_t) * right->cnt;
        memcpy(to, from, len);
        memset(from, 0, len);

        left->cnt = BTREE_LEAF_HALF_CNT;

        moved_key = btree_leaf_key_ptr(left, BTREE_LEAF_HALF_CNT - 1);

        right->right = left->right;
        if (right->right) {
            leaf_header_t *next;

            balloc_read(btree->balloc, right->right, (void **)&next);
            next->left = right_blkno;
        }
        right->left = left_blkno;
        left->right = right_blkno;
    } else {
        node_header_t *left = left_raw;
        node_header_t *right = right_raw;

        btree_init_node(right, right_blkno);
        right->level = left->level;
        right->cnt = BTREE_NODE_HALF_CNT;

        /* [0, half - 1], half, [half + 1, 2 * half] */
        to = btree_node_key_ptr(right, 0);
        from = btree_node_key_ptr(left, BTREE_NODE_HALF_CNT + 1);
        len = sizeof(bkey_t) * right->cnt;
        memcpy(to, from, len);
        memset(from, 0, len);

        /* [0, half], [half + 1, 2 * half + 1] */
        to = btree_node_data_ptr(right, 0);
        from = btree_node_data_ptr(left, BTREE_NODE_HALF_CNT + 1);
        len = sizeof(bndata_t) * (right->cnt + 1);
        memcpy(to, from, len);
        memset(from, 0, len);

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
    len = sizeof(bndata_t) * (node->cnt - idx);
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

    *(bkey_t *)btree_leaf_key_ptr(leaf, i) = *key;
    *(bdata_t *)btree_leaf_data_ptr(leaf, i) = *data;

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
        btree_insert_node_nonfull(btree, raw, key, data);
    else
        btree_insert_leaf_nonfull(btree, raw, key, data);

    return 0;
}

int btree_insert(btree_t *btree, const bkey_t *key, const bdata_t *data)
{
    int level = btree->level;
    void *root = btree->root;

    if (btree_nl_is_full(level, root)) {
        uint32_t blkno;
        node_header_t *node;
        bndata_t *ndata;

        balloc_alloc_read(btree->balloc, &blkno, (void **)&node);

        btree_init_node(node, blkno);
        node->level = btree->level + 1;

        ndata = btree_node_data_ptr(node, 0);
        ndata->blkno = btree_root_blkno(btree);

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

int btree_need_update_for_del(int plevel, void *child)
{
    int need_update = 0;

    if (plevel != 1) {
        struct node_header_t *cnode = child;

        need_update = cnode->cnt <= BTREE_NODE_HALF_CNT;
    } else {
        struct leaf_header_t *cleaf = child;

        need_update = cleaf->cnt <= BTREE_LEAF_HALF_CNT;
    }

    return need_update;
}

void *btree_steal_node(btree_t *btree, node_header_t *node, unsigned int key_idx,
        node_header_t *src, unsigned int src_key_idx, unsigned int src_data_idx,
        node_header_t *dst, unsigned int dst_key_idx, unsigned int dst_data_idx)
{
    bkey_t *parent_key;
    bkey_t *src_key;
    bndata_t *src_ndata;
    bkey_t new_key;
    bndata_t new_ndata;
    void *from;
    void *to;
    size_t len;

    parent_key = btree_node_key_ptr(node, key_idx);
    src_ndata = btree_node_data_ptr(src, src_data_idx);
    new_key = *parent_key;
    new_ndata = *src_ndata;

    /* insert into position dst_key_idx */
    if (dst_key_idx < dst->cnt) {
        from = btree_node_key_ptr(dst, dst_key_idx);
        to = btree_node_key_ptr(dst, dst_key_idx + 1);
        len = sizeof(bkey_t) * (dst->cnt - dst_key_idx);
        memmove(to, from, len);

        from = btree_node_data_ptr(dst, dst_key_idx);
        to = btree_node_data_ptr(dst, dst_key_idx + 1);
        len = sizeof(bndata_t) * (dst->cnt + 1 - dst_key_idx);
        memmove(to, from, len);
    }

    *(bkey_t *)btree_node_key_ptr(dst, dst_key_idx) = new_key;
    *(bndata_t *)btree_node_data_ptr(dst, dst_data_idx) = new_ndata;

    dst->cnt += 1;

    /* replace key in parent node */
    src_key = btree_node_key_ptr(src, src_key_idx);
    *parent_key = *src_key;

    /* remove src_key_idx from src */
    if (src_key_idx + 1 < src->cnt) {
        from = btree_node_key_ptr(dst, src_key_idx + 1);
        to = btree_node_key_ptr(dst, src_key_idx);
        len = sizeof(bkey_t) * (dst->cnt - src_key_idx - 1);
        memmove(to, from, len);

        from = btree_node_data_ptr(dst, src_key_idx + 1);
        to = btree_node_data_ptr(dst, src_key_idx);
        len = sizeof(bndata_t) * (dst->cnt - src_key_idx);
        memmove(to, from, len);
    }

    src_key = btree_node_key_ptr(src, src->cnt - 1);
    src_ndata = btree_node_data_ptr(src, src->cnt);
    memset(src_key, 0, sizeof(*src_key));
    memset(src_ndata, 0, sizeof(*src_ndata));
    src->cnt -= 1;

    return dst;
}

void btree_node_remove_key_ndata(node_header_t *node, unsigned int key_idx)
{
    void *from;
    void *to;
    size_t len;

    /* remove & clear a parent key & ndata */
    if (key_idx + 1 < node->cnt) {
        from = btree_node_key_ptr(node, key_idx + 1);
        to = btree_node_key_ptr(node, key_idx);
        len = sizeof(bkey_t) * (node->cnt - key_idx - 1);
        memmove(to, from, len);

        from = btree_node_data_ptr(node, key_idx + 2);
        to = btree_node_data_ptr(node, key_idx + 1);
        len = sizeof(bndata_t) * (node->cnt - key_idx - 1);
        memmove(to, from, len);
    }
    from = btree_node_key_ptr(node, node->cnt - 1);
    len = sizeof(bkey_t);
    memset(from, 0, len);

    from = btree_node_data_ptr(node, node->cnt);
    len = sizeof(bndata_t);
    memset(from, 0, len);

    node->cnt -= 1;
}

void *btree_merge_node(btree_t *btree, node_header_t *node, node_header_t *dst,
        node_header_t *src, unsigned int key_idx)
{
    void *from;
    void *to;
    size_t len;

    /* append parent key to dst node */
    from = btree_node_key_ptr(node, key_idx);
    to = btree_node_key_ptr(dst, dst->cnt);
    len = sizeof(bkey_t);
    memcpy(to, from, len);
    dst->cnt += 1;

    /* append src key & ndata to dst node */
    from = btree_node_key_ptr(src, 0);
    to = btree_node_key_ptr(dst, dst->cnt);
    len = sizeof(bkey_t) * src->cnt;
    memcpy(to, from, len);

    from = btree_node_data_ptr(src, 0);
    to = btree_node_data_ptr(dst, dst->cnt);
    len = sizeof(bndata_t) * (src->cnt + 1);
    memcpy(to, from, len);

    dst->cnt += src->cnt;
    assert(dst->cnt <= BTREE_NODE_FULL_CNT);

    /* remove src */
    balloc_free(btree->balloc, src->blkno);

    /* remove & clear a parent key & ndata */
    btree_node_remove_key_ndata(node, key_idx);

    /* reduce the height if necessary */
    if (node->cnt == 0) {
        assert(btree->root == node);

        btree->level -= 1;
        btree->root = dst;

        balloc_free(btree->balloc, node->blkno);
    }

    return dst;
}

void *btree_update_node_for_del(btree_t *btree, node_header_t *node, node_header_t *child,
        unsigned int data_idx)
{
    node_header_t *left = NULL;
    node_header_t *right = NULL;
    bndata_t *ndata;

    if (data_idx > 0) {
        ndata = btree_node_data_ptr(node, data_idx - 1);
        balloc_read(btree->balloc, ndata->blkno, (void **)&left);

        if (left->cnt > BTREE_NODE_HALF_CNT)
            return btree_steal_node(btree, node, data_idx - 1,
                    left, left->cnt - 1, left->cnt,
                    child, 0, 0);
    }

    if (data_idx < node->cnt) {
        ndata = btree_node_data_ptr(node, data_idx + 1);
        balloc_read(btree->balloc, ndata->blkno, (void **)right);
        if (right->cnt > BTREE_NODE_HALF_CNT)
            return btree_steal_node(btree, node, data_idx,
                    right, 0, 0,
                    child, child->cnt, child->cnt + 1);
    }

    if (left)
        return btree_merge_node(btree, node, left, child, data_idx - 1);
    else
        return btree_merge_node(btree, node, child, right, data_idx);
}

void *btree_steal_leaf(btree_t *btree, node_header_t *node, unsigned int key_idx,
        leaf_header_t *src, unsigned int src_key_idx, unsigned int src_up_key_idx,
        leaf_header_t *dst, unsigned int dst_key_idx)
{
    bkey_t *parent_key;
    bkey_t *src_key;
    bdata_t *src_data;
    bkey_t new_key;
    bdata_t new_data;
    void *from;
    void *to;
    size_t len;

    src_key = btree_leaf_key_ptr(src, src_key_idx);
    src_data = btree_leaf_data_ptr(src, src_key_idx);
    new_key = *src_key;
    new_data = *src_data;

    /* insert into position dst_key_idx */
    if (dst_key_idx < dst->cnt) {
        from = btree_leaf_key_ptr(dst, dst_key_idx);
        to = btree_leaf_key_ptr(dst, dst_key_idx + 1);
        len = sizeof(bkey_t) * (dst->cnt - dst_key_idx);
        memmove(to, from, len);

        from = btree_leaf_data_ptr(dst, dst_key_idx);
        to = btree_leaf_data_ptr(dst, dst_key_idx + 1);
        len = sizeof(bdata_t) * (dst->cnt - dst_key_idx);
        memmove(to, from, len);
    }

    *(bkey_t *)btree_leaf_key_ptr(dst, dst_key_idx) = new_key;
    *(bdata_t *)btree_leaf_data_ptr(dst, dst_key_idx) = new_data;

    dst->cnt += 1;

    /* replace key in parent node */
    parent_key = btree_node_key_ptr(node, key_idx);
    src_key = btree_leaf_key_ptr(src, src_up_key_idx);
    *parent_key = *src_key;

    /* remove src_key_idx from src */
    if (src_key_idx + 1 < src->cnt) {
        from = btree_leaf_key_ptr(dst, src_key_idx + 1);
        to = btree_leaf_key_ptr(dst, src_key_idx);
        len = sizeof(bkey_t) * (dst->cnt - src_key_idx - 1);
        memmove(to, from, len);

        from = btree_leaf_data_ptr(dst, src_key_idx + 1);
        to = btree_leaf_data_ptr(dst, src_key_idx);
        len = sizeof(bdata_t) * (dst->cnt - src_key_idx - 1);
        memmove(to, from, len);
    }

    src_key = btree_leaf_key_ptr(src, src->cnt - 1);
    src_data = btree_leaf_data_ptr(src, src->cnt - 1);
    memset(src_key, 0, sizeof(*src_key));
    memset(src_data, 0, sizeof(*src_data));
    src->cnt -= 1;

    return dst;
}

void *btree_merge_leaf(btree_t *btree, node_header_t *node, leaf_header_t *dst,
        leaf_header_t *src, unsigned int key_idx)
{
    void *from;
    void *to;
    size_t len;

    /* append src key & data to dst node */
    from = btree_leaf_key_ptr(src, 0);
    to = btree_leaf_key_ptr(dst, dst->cnt);
    len = sizeof(bkey_t) * src->cnt;
    memcpy(to, from, len);

    from = btree_leaf_data_ptr(src, 0);
    to = btree_leaf_data_ptr(dst, dst->cnt);
    len = sizeof(bdata_t) * src->cnt;
    memcpy(to, from, len);

    dst->cnt += src->cnt;
    assert(dst->cnt <= BTREE_LEAF_FULL_CNT);

    /* remove src */
    balloc_free(btree->balloc, src->blkno);

    /* remove & clear a parent key & data */
    btree_node_remove_key_ndata(node, key_idx);

    /* reduce the height if necessary */
    if (node->cnt == 0) {
        assert(btree->root == node);

        btree->level -= 1;
        btree->root = dst;

        balloc_free(btree->balloc, node->blkno);
    }

    return dst;
}

void *btree_update_leaf_for_del(btree_t *btree, node_header_t *node, leaf_header_t *child,
        unsigned int data_idx)
{
    leaf_header_t *left = NULL;
    leaf_header_t *right = NULL;
    bndata_t *ndata;

    if (data_idx > 0) {
        ndata = btree_node_data_ptr(node, data_idx - 1);
        balloc_read(btree->balloc, ndata->blkno, (void **)&left);

        if (left->cnt > BTREE_LEAF_HALF_CNT)
            return btree_steal_leaf(btree, node, data_idx - 1,
                    left, left->cnt - 1, left->cnt - 2,
                    child, 0);
    }

    if (data_idx < node->cnt) {
        ndata = btree_node_data_ptr(node, data_idx + 1);
        balloc_read(btree->balloc, ndata->blkno, (void **)right);
        if (right->cnt > BTREE_LEAF_HALF_CNT)
            return btree_steal_leaf(btree, node, data_idx,
                    right, 0, 0,
                    child, child->cnt);
    }

    if (left)
        return btree_merge_leaf(btree, node, left, child, data_idx - 1);
    else
        return btree_merge_leaf(btree, node, child, right, data_idx);
}

void *btree_update_for_del(btree_t *btree, node_header_t *node, void *child, unsigned int data_idx)
{
    if (node->level != 1)
        return btree_update_node_for_del(btree, node, child, data_idx);
    else
        return btree_update_leaf_for_del(btree, node, child, data_idx);
}

int btree_delete_leaf(btree_t *btree, leaf_header_t *leaf, const bkey_t *key, bdata_t *data)
{
    assert(btree->root == leaf || leaf->cnt > BTREE_LEAF_HALF_CNT);
    bkey_t *cur_key;
    int cmp = 1;
    int i;
    void *from;
    void *to;
    size_t len;

    for (i = 0, cur_key = btree_leaf_key_ptr(leaf, 0); i < leaf->cnt;
            i++, cur_key++) {
        cmp = btree_cmp_key(key, cur_key);
        if (cmp <= 0)
            break;
    }

    if (cmp != 0)
        return -1;

    *data = *(bdata_t *)btree_leaf_data_ptr(leaf, i);

    if (i + 1 < leaf->cnt) {
        to = btree_leaf_key_ptr(leaf, i + 1);
        from = btree_leaf_key_ptr(leaf, i);
        len = sizeof(bkey_t) * (leaf->cnt - i - 1);
        memmove(to, from, len);

        to = btree_leaf_data_ptr(leaf, i + 1);
        from = btree_leaf_data_ptr(leaf, i);
        len = sizeof(bdata_t) * (leaf->cnt - i - 1);
        memmove(to, from, len);
    }

    from = btree_leaf_key_ptr(leaf, leaf->cnt - 1);
    len = sizeof(bkey_t);
    memset(from, 0, len);

    from = btree_leaf_data_ptr(leaf, leaf->cnt - 1);
    len = sizeof(bdata_t);
    memset(from, 0, len);

    leaf->cnt -= 1;

    return 0;
}

int btree_delete_node(btree_t *btree, node_header_t *node, const bkey_t *key, bdata_t *data)
{
    int ret = 0;
    void *child;
    bkey_t *nkey;
    bndata_t *ndata;
    unsigned int i;

    assert(btree->root == node || node->cnt > BTREE_NODE_HALF_CNT);

    for (i = 0, nkey = btree_node_key_ptr(node, 0);
            i < node->cnt; i++, nkey++) {
        if (btree_cmp_key(key, nkey) <= 0)
            break;
    }

    ndata = btree_node_data_ptr(node, i);
    balloc_read(btree->balloc, ndata->blkno, &child);
    if (btree_need_update_for_del(node->level, child)) {
        /* child maybe freed and changed */
        child = btree_update_for_del(btree, node, child, i);
    }

    if (node->level != 1)
        ret = btree_delete_node(btree, child, key, data);
    else
        ret = btree_delete_leaf(btree, child, key, data);

    return ret;
}

int btree_delete(btree_t *btree, const bkey_t *key, bdata_t *data)
{
    /*
     * ensure there are at least half + 1 key in node.
     * 1. key cnt of leaf >= half + 1
     *    remove the key & data
     * 2. key cnt of leaf <= half, the key cnt of siblings also <= half
     *    merge it with one sibling, remove a key from parent
     *    if parent is root and it has only one key, reduce the root level
     * 3. key cnt of leaf <= half, the key cnt of one sibling >= half + 1
     *    move a key & data from the sibiling, update the key of parent
     */
    int ret;
    int level = btree->level;
    void *root = btree->root;

    /* lookup down through the btree */
    if (level != 0)
        ret = btree_delete_node(btree, root, key, data);
    else
        ret = btree_delete_leaf(btree, root, key, data);

    return ret;
}

void btree_dump_leaf(leaf_header_t *leaf)
{
    bkey_t *key;
    unsigned int i;

    printf("leaf blk %u, left %u, right %u, cnt %u\n",
            leaf->blkno, leaf->left, leaf->right, leaf->cnt);

    if (verbose) {
        const int group = 5;
        bdata_t *data;

        key = btree_leaf_key_ptr(leaf, 0);
        data = btree_leaf_data_ptr(leaf, 0);
        for (i = 0; i < leaf->cnt; i++, key++, data++) {
            if (i % group != 0)
                printf("  ");

            printf("[%u]=%llu:%llu", i, key->offset, data->start);

            if (i % group == group - 1)
                printf("\n");
        }
        if (i % group != 0)
            printf("\n");
    } else {
        unsigned int step = leaf->cnt / 5;

        for (i = 0; i < leaf->cnt; i += step) {
            key = btree_leaf_key_ptr(leaf, i);
            if (i != 0)
                printf("  ");
            printf("[%u]=%llu", i, key->offset);
        }
        if (i != leaf->cnt - 1) {
            key = btree_leaf_key_ptr(leaf, leaf->cnt - 1);
            printf("  [%u]=%llu", leaf->cnt - 1, key->offset);
        }
    }
    printf("\n");
}

/* breadth-first */
void btree_dump_node(btree_t *btree, node_header_t *node)
{
    const unsigned int group = 8;
    int i;
    bkey_t *key;
    bndata_t *ndata;

    printf("node level %u, blk %u, cnt %u (half %u, full %u)\n",
            node->level, node->blkno, node->cnt,
            BTREE_NODE_HALF_CNT, BTREE_NODE_FULL_CNT);
    key = btree_node_key_ptr(node, 0);
    for (i = 0; i < node->cnt; i++, key++) {
        if (i % group != 0)
            printf("  ");

        printf("[%u]=%llu", i, key->offset);

        if (i % group == group - 1)
            printf("\n");
    }
    if (i % group != 0)
        printf("\n");

    ndata = btree_node_data_ptr(node, 0);
    for (i = 0; i < node->cnt + 1; i++, ndata++) {
        if (i % group != 0)
            printf("  ");

        printf("[%u]=%u", i, ndata->blkno);

        if (i % group == group - 1)
            printf("\n");
    }
    if (i % group != 0)
        printf("\n");
    printf("\n");

    ndata = btree_node_data_ptr(node, 0);
    for (i = 0; i < node->cnt + 1; i++, ndata++) {
        void *raw;

        balloc_read(btree->balloc, ndata->blkno, &raw);
        if (node->level != 1)
            btree_dump_node(btree, raw);
        else
            btree_dump_leaf(raw);
    }
}

void btree_dump(btree_t *btree)
{
    void *root = btree->root;

    if (btree->level)
        btree_dump_node(btree, root);
    else
        btree_dump_leaf(root);
}

int main(int argc, char **argv)
{
    int cnt = 1024;
    ballocator_t *balloc;
    btree_t *btree;
    int i;
    int ret;
    bkey_t key;
    bdata_t data;

    if (argc >= 2)
        cnt = atoi(argv[1]);

    if (argc >= 3)
        verbose = 1;

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
        if (ret != 0) {
            printf("%d not found\n", i);
            exit(1);
        } else if (data.start != i) {
            printf("%d exp %d, got %llu\n", i, i, data.start);
            exit(1);
        }
    }

    btree_dump(btree);

    for (i = 0; i < cnt; i++) {
        ret = btree_delete(btree, &key, &data);
        if (ret != 0) {
            printf("del %d: not found\n", i);
            exit(1);
        } else if (data.start != i) {
            printf("del %d: exp %d, got %llu\n", i, i, data.start);
            exit(1);
        }
    }

    balloc_exit(balloc);

    return 0;
}
