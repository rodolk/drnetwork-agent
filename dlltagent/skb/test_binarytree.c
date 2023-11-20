#include <stdio.h>
#include <stdlib.h>
#include "binarytree.h"

int main()
{
    keytype key = 1901;
    bnode_t *root;
    int res, i;

    res = init_binary_tree();
    if (res < 0)
    {
        printf("CRITICAL error initializing binary tree\n");
        exit(2);
    }
    res = init_root(&root, 200, (datatype) 200);
    if (res < 0)
    {
        printf("CRITICAL error initializing root node\n");
        exit(3);
    }

    printf("BEGIN\n");
    searchnode(key, root);
    for(i = 0; i < 1000000; i++) addnode((keytype)i, (datatype)i, &root);
    
    printf("CONT\n");
    if (searchnode(8, root)) printf("found %d\n", 8);
    if (searchnode(978780, root)) printf("found %d\n", 978780);
    searchnode(190, root);
    searchnode(73, root);
    searchnode(157, root); 
    searchnode(1570, root); 
    if (!searchnode(9787800, root)) printf("NOT found %d\n", 9787800);

    
    deletenode(8, &root);
    if (!searchnode(8, root)) printf("NOT found %d\n", 8);

    for(i = 0; i < 999999; i++) deletenode((keytype)i, &root);
    print_tree(root, 0);
    if (searchnode(999999, root)) printf("found %d\n", 999999);
    if (!searchnode(999998, root)) printf("NOT found %d\n", 999998);
    
    deletenode((keytype)999999, &root);
    
    res = init_root(&root, 0, (datatype)0);
    if (res < 0)
    {
        printf("CRITICAL error initializing root node\n");
        exit(3);
    }
    
    for(i = 1; i < 1000000; i++)
    {
    	addnode((keytype)i, (datatype)i, &root);
    }
    
    for(i = 35; i < 1000000; i++)
    {
    	deletenode((keytype)i, &root);
    }
    for(i = 1; i < 1000000; i++)
    {
    	addnode((keytype)i, (datatype)i, &root);
    }
    for(i = 999991; i > 10; i--)
    {
    	deletenode((keytype)i, &root);
    }
	printf("PRINT TREE - i = %d--------------------------------------\n\n", i);
    print_tree(root, 0);

    return 0;
}
