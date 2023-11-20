#ifndef BINARYTREE_EXP_H
#define BINARYTREE_EXP_H

#include <stdint.h>

#include "binarytree.h"

extern "C" {
    int init_binary_tree();
    int init_root(bnode_t **root, treekey_t *key, datatype data);
    void addnode(treekey_t *key, datatype data, bnode_t **root);
    bnode_t *searchnode(treekey_t *key, bnode_t *sroot);
    void print_tree(bnode_t *root, uint16_t indent);
    void deletenode(treekey_t *key, bnode_t **root);
    void releaseAllBinaryTreeMemory();
};

#endif /* BINARYTREE_EXP_H */
