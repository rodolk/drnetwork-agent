#ifndef BINARYTREE_H
#define BINARYTREE_H

#include <stdint.h>

typedef struct {
    uint64_t treeIPKey;
    uint32_t treePortKey;
} treekey_t;

typedef void*  datatype;

struct bnode
{
    treekey_t key;
    struct bnode *child[2];
    uint8_t h[2];
    uint8_t height;
    struct bnode *parent;
    datatype data;
};

typedef struct bnode bnode_t;


#define KEY_EQUAL(key1, key2) (((key1).treeIPKey == (key2).treeIPKey) && ((key1).treePortKey == (key2).treePortKey))

#define KEY_LESSTHAN(key1, key2) \
    (((key1).treeIPKey < (key2).treeIPKey) ? 1 : \
     (((key1).treeIPKey == (key2).treeIPKey) && ((key1).treePortKey < (key2).treePortKey)) ? 1 : 0)

#define KEY_GREATERTHAN(key1, key2) \
        (((key1).treeIPKey > (key2).treeIPKey) ? 1 : \
         (((key1).treeIPKey == (key2).treeIPKey) && ((key1).treePortKey > (key2).treePortKey)) ? 1 : 0)
/*
extern "C" {
    int init_binary_tree();
    int init_root(bnode_t **root, treekey_t *key, datatype data);
    void addnode(treekey_t *key, datatype data, bnode_t **root);
    bnode_t *searchnode(treekey_t *key, bnode_t *sroot);
    void print_tree(bnode_t *root, uint16_t indent);
    void deletenode(treekey_t *key, bnode_t **root);
}
*/
#endif /* BINARYTREE_H */
