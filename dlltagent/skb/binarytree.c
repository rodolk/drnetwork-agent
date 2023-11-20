#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "binarytree.h"

#undef GDB_SRV        


#define MAX_ARRAYS 100
#define MAX_NODES_IN_ARRAY 100000

#define SET_HEIGHT(node) \
    node->height = (node->h[0] > node->h[1]) ? node->h[0] : node->h[1];

typedef struct link
{
    bnode_t *node;
    struct link *next;
} link_t;


static void delete_node(bnode_t *node);
static void add_empty_link_list(link_t *link);
static bnode_t *get_new_node();
static link_t *get_link();

static bnode_t *balance_tree(bnode_t *node);
static void b_balance(bnode_t *node);
static bnode_t *b_search_node(bnode_t *node, treekey_t *key);
static bnode_t *b_insert_node(bnode_t *node, treekey_t *key, datatype data);
static bnode_t *create_child_node(treekey_t *key, datatype data, bnode_t *parent, uint8_t idx);
static bnode_t *force_balance_tree(bnode_t *node);

bnode_t *searchnode(treekey_t *key, bnode_t *sroot);

bnode_t *arrays_nodes[MAX_ARRAYS];
uint32_t arrays_indexes[MAX_ARRAYS];
uint16_t num_arrays;
uint16_t curr_array;

bnode_t arraynodes[MAX_NODES_IN_ARRAY];


/**
 * There are two main lists:
 *  -head: contains links pointing to the bnode_t's that were returned because a node was deleted from the btree.
 *         These bnode_t's are available to use for another tree node.
 *  -head_empty: this is the header of a list of link_t structs that are available to use to add a "new" deleted bnode_t
 *               to head. When a bnode_t is removed from head, the corresponding link_t is added to head_empty list.
 *               link_t structs in this list are not pointing to a valid bnode_t.
 *
 * When a new node is requested, calling function get_new_node, and head is empty, it gets a new node from pre-allocated memory pointed to by
 * a 2-dim array arrays_nodes.
 * array_nodes points to various arrays of bnode_t structs of size MAX_NODES_IN_ARRAY. It can point to up to MAX_ARRAYS.
 * The array in index 0 is pre-allocated from the beginning, statically, in arraynodes. Thus, it is not necessary to allocate
 * memory at the initiation phase.
 * Trees are identified by there root passed as parameter.
 * addnode, deletenode, searchnode, print_tree, and init_binary_tree are the public functions that can be called.
 *
 */

static link_t *head = NULL;
static link_t *head_empty = NULL;




static bnode_t *get_greatest(bnode_t *node) {
    if (node->child[1]) {
        return get_greatest(node->child[1]);
    }
    else {
        return node;
    }
}

static bnode_t *get_least(bnode_t *node)
{
    if (node->child[0])
    {
        return get_least(node->child[0]);
    }
    else
    {
        return node;
    }
} 

/**
 * Description:
 * This function has to be called always at the very beginning before using any
 * binary tree functionality.
 *
 * Returns
 * int always 0 unless somebody modifies the code :)
 *
 */
int init_binary_tree()
{
    arrays_nodes[0] = arraynodes;
    curr_array = 0;
    num_arrays = 1;
    
    head = NULL;
    head_empty = NULL;

    return 0;
}

/**
 * Description
 * This function creates the very first node of a new tree.
 *
 * Returns
 * int o if everything is OK, -1 if a new node cannot be obtained.
 *
 */
int init_root(bnode_t **root, treekey_t *key, datatype data) {
    *root = get_new_node();
    
    if (!*root) {
        printf("CRITICAL ERROR: Could not get root\n");
        return -1;
    } else {
        (*root)->parent = NULL;
        (*root)->key = *key;
        (*root)->child[0] = 0;
        (*root)->child[1] = 0;
        (*root)->h[0] = 0;
        (*root)->h[1] = 0;
        (*root)->height = 0;
        (*root)->data = data;
    }
    
    return 0;
}

/**
 * Description:
 * This function adds a node with key and pointing to data under root.
 * root can change after the tree is rebalanced after new node is inserted by b_insert_node.
 * If the new node has no parent then this is the new root.
 *
 * Parameters:
 * key
 * data
 * root **     root of tree. It can change.
 */
void addnode(treekey_t *key, datatype data, bnode_t **root) {
    bnode_t *root2;
    bnode_t *aux;
    aux = b_insert_node(*root, key, data);

    if (aux) {
        if (aux->parent) {
            root2 = balance_tree(aux->parent);
            if (root2) *root = root2;
        } else {
            *root = aux;
        }
    }
}

/**
 * Description:
 * This function removes a bnode_t with the key provided in key, from the tree with root root :)
 * The function also keeps the tree balanced and at the end it will finally free the bnode_t
 * that is removed from the tree to make it available for a new node to add to any tree.
 * At the end it calls delete_node to free the node_t.
 * When a node is removed, it is possible that the tree's root changes. This is why root is a
 * pointer to pointer.
 *
 * Parameters:
 *
 * key  this is the key to be removed
 * root the root of the tree from which the bnode_t with given key is removed.
 *      This is a pointer to pointer because the tree's root can change after removing a node.
 *
 */
void deletenode(treekey_t *key, bnode_t **root)
{
    bnode_t *node;
    bnode_t *root2;

    node = searchnode(key, *root);

    if (node)
    {
        if (!node->child[0] && !node->child[1]) //leaf
        {
            if (node->parent)
            {
                if (node->parent->child[0] == node)
                {
                    node->parent->child[0] = NULL;
                    node->parent->h[0] = 0;
                }
                else
                {
                    node->parent->child[1] = NULL;
                    node->parent->h[1] = 0;
                }
                SET_HEIGHT(node->parent);

                root2 = balance_tree(node->parent);
                if (root2) *root = root2;
            }
            else
            {
                *root = NULL;
            }
        }
        else //not a leaf - Need to find a replacement
        {
            bnode_t *replace_node;

            if (node->h[0] >= node->h[1])
            {
                replace_node = get_greatest(node->child[0]);

                if (replace_node)
                {
                    if (replace_node != node->child[0])
                    {
                        replace_node->parent->h[1] = replace_node->h[0];
                        replace_node->parent->child[1] = replace_node->child[0];
                        if (replace_node->h[0] > 0) //Has left child
                        {
                            replace_node->child[0]->parent = replace_node->parent;
                        } //else it's leaf -> done
                    }

                } //else error
            }
            else
            {
                replace_node = get_least(node->child[1]);

                if (replace_node)
                {
                    if (replace_node != node->child[1])
                    {
                        replace_node->parent->h[0] = replace_node->h[1];
                        replace_node->parent->child[0] = replace_node->child[1];
                        if (replace_node->h[1] > 0) //Has right child
                        {
                            replace_node->child[1]->parent = replace_node->parent; //Not necessary if parent is node
                        } //else it's leaf -> done
                    }

                } //else error
            }

            if (replace_node)
            {
                bnode_t *aux = replace_node->parent;

                replace_node->parent = node->parent; //Here there is a new replace_node->parent

                if (node->child[0] != replace_node)
                {
                    replace_node->child[0] = node->child[0];
                    if (replace_node->child[0])
                    {
                        replace_node->child[0]->parent = replace_node;
                    }
                    replace_node->h[0] = node->h[0];
                }

                if (node->child[1] != replace_node)
                {
                    replace_node->child[1] = node->child[1];
                    if (replace_node->child[1])
                    {
                        replace_node->child[1]->parent = replace_node;
                    }
                    replace_node->h[1] = node->h[1];
                }

                SET_HEIGHT(replace_node);

                if (replace_node->parent)
                {
                    if (replace_node->parent->child[0] == node)
                    {
                        replace_node->parent->child[0] = replace_node;
                    }
                    else
                    {
                        replace_node->parent->child[1] = replace_node;
                    }
                }

                if (aux != node)
                {
                    aux->h[0] = aux->child[0] ? aux->child[0]->height + 1 : 0;
                    aux->h[1] = aux->child[1] ? aux->child[1]->height + 1 : 0;
                    SET_HEIGHT(aux);
                    *root = force_balance_tree(aux); //TODO: WE don't need to go up to the root
                }
                else
                {
                    *root = force_balance_tree(replace_node); //TODO: WE don't need to go up to the root
                }
            } //else error
        }

        delete_node(node);
    }
}



bnode_t *force_balance_tree(bnode_t *node)
{
    bnode_t *parent = node->parent; // we are not checking if node is NULL

    if (parent == NULL)
    {
        b_balance(node);

        if (node->parent)
        {
            return node->parent;
        }
        else
        {
            return node;
        }
    }
    else
    {
        b_balance(node);
        parent->h[0] = parent->child[0] ? parent->child[0]->height + 1 : 0;
        parent->h[1] = parent->child[1] ? parent->child[1]->height + 1 : 0;
        SET_HEIGHT(parent);
        return force_balance_tree(parent);
    }
}


/*
 * Print tree in preorder mode
 */
void print_tree(bnode_t *root, uint16_t indent)
{
    uint16_t j = indent;
    while(j--)
    {
        printf(" ");
    }
    printf("NODE: IPs: %lu - Ports: %u - height: %u - h[0]: %u - h[1]: %u\n", (long unsigned int)(root->key.treeIPKey), (root->key.treePortKey), root->height, root->h[0], root->h[1]);
    if (root->child[0])
    {
        j = indent;
        while(j--)
        {
            printf(" ");
        }
        printf("LEFT SUBTREE\n");
        print_tree(root->child[0], indent + 1);
    }
    if (root->child[1])
    {
        j = indent;
        while(j--)
        {
            printf(" ");
        }
        printf("RIGHT SUBTREE\n");
        print_tree(root->child[1], indent + 1);
    }
}


bnode_t *searchnode(treekey_t *key, bnode_t *sroot)
{
    bnode_t *aux;

#ifdef GDB_SRV        
    static int val = 0;
    uint8_t nk[6];
    int i;

    printf("ROOT: %lu\n", (long unsigned int)(sroot->key));
    printf("    CHILD-0: %lu\n", sroot->child[0] ? (long unsigned int)(sroot->child[0]->key) : 0);
    printf("    CHILD-1: %lu\n", sroot->child[1] ? (long unsigned int)(sroot->child[1]->key) : 0);
#endif

    aux = b_search_node(sroot, key);

    if (aux)
    {
#ifdef GDB_SRV        
        printf("FOUND-%d - ", val++);
        memcpy(nk, &(aux->key), 6);
        for(i=0;i<6;i++)
            printf("%2.2X", nk[i]);
        printf(" - ");
        memcpy(nk, &(sroot->key), 6);
        for(i=0;i<6;i++)
            printf("%2.2X", nk[i]);
        printf(" -\n\n");
#endif
        return aux;
    }
    else
    {
#ifdef GDB_SRV        
        printf("NOT FOUND %lu\n\n", (long unsigned int)key);
#endif
        return NULL;
    }
}    





bnode_t *balance_tree(bnode_t *node)
{
    bnode_t *parent = node->parent; // we are not checking if node is NULL
    uint16_t h0, h1;

    if (parent == NULL) //node is root
    {
        b_balance(node);

        if (node->parent) //after balance root changed
        {
            node = node->parent;
        }

        return node; //return root
    }
    else
    {
        h0 = parent->h[0];
        h1 = parent->h[1];

        b_balance(node);

        parent->h[0] = parent->child[0] ? parent->child[0]->height + 1 : 0;
        parent->h[1] = parent->child[1] ? parent->child[1]->height + 1 : 0;

        if (parent->h[0] != h0 || parent->h[1] != h1)
        {
            SET_HEIGHT(parent);
            return balance_tree(parent);
        }
        else
        {
            return NULL; //Root did not change
        }
    }
}


void b_balance(bnode_t *node)
{
    bnode_t *child;
    
    if (node->h[0] - node->h[1] == 2) //L
    {
        //node->child[0] always exists in this case parce que h[0] > 0
        child = node->child[0];

        if (child->h[0] >= child->h[1]) //LL
        {
            bnode_t *aux1 = child->child[1];
            child->child[1] = node;
            child->parent = node->parent;
            node->parent = child;
            node->child[0] = aux1;
            
            if (aux1)
            {
                aux1->parent = node;
            }
            
               node->h[0] = child->h[1];
               node->height = (node->h[0] > node->h[1]) ? node->h[0] : node->h[1];
               child->h[1] = node->height + 1;
               child->height = (child->h[0] > child->h[1]) ? child->h[0] : child->h[1];

               if (child->parent)
               {
                   if (child->parent->child[0] == node)
                   {
                       child->parent->child[0] = child;
                       //child->parent->h[0] = child->height + 1;
                   }
                   else
                   {
                       child->parent->child[1] = child;
                       //child->parent->h[1] = child->height + 1;
                   }
                   //child->parent->height = (child->parent->h[0] > child->parent->h[1]) ? child->parent->h[1] : child->parent->h[0];
               }
        }
        else //LR
        {
            bnode_t *aux1 = child->child[1];
            bnode_t *aux2 = aux1->child[0];
            bnode_t *aux3 = aux1->child[1];
            aux1->child[1] = node;
            aux1->child[0] = child;
            aux1->parent = node->parent;
            
            child->child[1] = aux2;
            child->parent = aux1;
            node->parent = aux1;
            node->child[0] = aux3;
            
            if (aux2)
            {
                aux2->parent = child;
            }
            if (aux3)
            {
                aux3->parent = node;
            }
            
            node->h[0] = aux1->h[1];
            child->h[1] = aux1->h[0];
            child->height = (child->h[0] > child->h[1]) ? child->h[0] : child->h[1];
            node->height = (node->h[0] > node->h[1]) ? node->h[0] : node->h[1];
            aux1->h[0] = child->height + 1;
            aux1->h[1] = node->height + 1;
            aux1->height = (aux1->h[0] > aux1->h[1]) ? aux1->h[0] : aux1->h[1];
            
            if (aux1->parent)
            {
                if (aux1->parent->child[0] == node)
                {
                    aux1->parent->child[0] = aux1;
                    //aux1->parent->h[0] = aux1->height + 1;
                }
                else
                {
                    aux1->parent->child[1] = aux1;
                    //aux1->parent->h[1] = aux1->height + 1;
                }
                //aux1->parent->height = (aux1->parent->h[0] > aux1->parent->h[1]) ? aux1->parent->h[0] : aux1->parent->h[1];
            }

        }
    }
    else
    {
        if (node->h[1] - node->h[0] == 2) //R
        {
            //node->child[1] always exists in this case parce que h[1] > 0
            child = node->child[1];

            if (child->h[1] >= child->h[0]) //RR
            {
                bnode_t *aux1 = child->child[0];
                child->child[0] = node;
                child->parent = node->parent;
                node->parent = child;
                node->child[1] = aux1;
                
                if (aux1)
                {
                    aux1->parent = node;
                }
                
                   node->h[1] = child->h[0];
                   node->height = (node->h[0] > node->h[1]) ? node->h[0] : node->h[1];
                   child->h[0] = node->height + 1;
                   child->height = (child->h[0] > child->h[1]) ? child->h[0] : child->h[1];

                   if (child->parent)
                   {
                       if (child->parent->child[0] == node)
                       {
                           child->parent->child[0] = child;
                           //child->parent->h[0] = child->height + 1;
                       }
                       else
                       {
                           child->parent->child[1] = child;
                           //child->parent->h[1] = child->height + 1;
                       }
                       //child->parent->height = (child->parent->h[0] > child->parent->h[1]) ? child->parent->h[1] : child->parent->h[0];
                   }
            }
            else //RL
            {
                bnode_t *aux1 = child->child[0];
                bnode_t *aux2 = aux1->child[1];
                bnode_t *aux3 = aux1->child[0];
                aux1->child[0] = node;
                aux1->child[1] = child;
                aux1->parent = node->parent;
                
                child->child[0] = aux2;
                child->parent = aux1;
                node->parent = aux1;
                node->child[1] = aux3;
                
                if (aux2)
                {
                    aux2->parent = child;
                }
                if (aux3)
                {
                    aux3->parent = node;
                }
                
                node->h[1] = aux1->h[0];
                child->h[0] = aux1->h[1];
                child->height = (child->h[0] > child->h[1]) ? child->h[0] : child->h[1];
                node->height = (node->h[0] > node->h[1]) ? node->h[0] : node->h[1];
                aux1->h[1] = child->height + 1;
                aux1->h[0] = node->height + 1;
                aux1->height = (aux1->h[0] > aux1->h[1]) ? aux1->h[0] : aux1->h[1];
                
                if (aux1->parent)
                {
                    if (aux1->parent->child[0] == node)
                    {
                        aux1->parent->child[0] = aux1;
                        //aux1->parent->h[0] = aux1->height + 1;
                    }
                    else
                    {
                        aux1->parent->child[1] = aux1;
                        //aux1->parent->h[1] = aux1->height + 1;
                    }
                    //aux1->parent->height = (aux1->parent->h[0] > aux1->parent->h[1]) ? aux1->parent->h[0] : aux1->parent->h[1];
                }
            }
        }
    }
}

    
    
bnode_t *b_search_node(bnode_t *node, treekey_t *key) {
    if (node == NULL) return NULL;
    
#ifdef GDB_SRV        
    printf("NODE'S KEY: %llu\n", (unsigned long long)node->key);
    printf("    NODE'S CHILDREN 0: %lu\n", node->child[0] ? (long unsigned int)node->child[0]->key : 0);
    printf("    NODE'S CHILDREN 1: %lu\n", node->child[1] ? (long unsigned int)node->child[1]->key : 0);
#endif
    
    if (KEY_EQUAL(*key, node->key)) {
        return node;
    }
    else if (KEY_LESSTHAN(*key, node->key)) {
        return b_search_node(node->child[0], key);
    }
    else {
        return b_search_node(node->child[1], key);
    }
}
    
/**
 * Description:
 * This is function inserts a new node with key and pointing to data, under the provided node.
 * It checks if the key already exists and also looks for the position of the new key in the tree,
 * if it doesn't exist.
 * This is a recursive function always searching key under received bnode_t.
 * It creates a new node calling function create_child_node.
 * If the bnode_t alreay exists, It keeps pointing to the previous data.
 *
 * Parameters:
 * node     is the root of the subtree where to search for key.
 * key      is the new key that is inserted.
 * data is the data to be inserted, pointed to by the new node.
 *
 */
bnode_t *b_insert_node(bnode_t *node, treekey_t *key, datatype data) {
    uint8_t idx;
    
    if (node == NULL) return NULL;
    
    if (KEY_LESSTHAN(*key, node->key)) {
        idx = 0;
    } else if (KEY_GREATERTHAN(*key, node->key)) {
        idx = 1;
    } else {
        return node;
    }
    
    if (node->child[idx]) {
        return b_insert_node(node->child[idx], key, data);
    }
    else {
        return create_child_node(key, data, node, idx);
    }
}


/**
 * Description:
 * This function creates a new child node for the provided key under the provided parent.
 * This new node will belong to a tree. The same tree as parent.
 * It obtains the child from get_new_node.
 * The new child node doesn't have children.
 * The new node points to the data provided.
 * The new node is not added to any list but to a tree.
 *
 * Parameters:
 * key      This is the key for the new node.
 * data     data to be pointed by this node.
 * parent   parent of the new node.
 * idx      index to one of the two possible children for a parent node.
 *
 * Returns:
 * bnode_t * already belonging to the tree, the same tree the parent belongs to.
 *
 */
bnode_t *create_child_node(treekey_t *key, datatype data, bnode_t *parent, uint8_t idx) {
    bnode_t *child = get_new_node();
    
    if (child) {
        child->parent = parent;
        child->key = *key;
        child->child[0] = 0;
        child->child[1] = 0;
        child->h[0] = 0;
        child->h[1] = 0;
        child->height = 0;
        child->data = data;
        parent->child[idx] = child;
        parent->h[idx] = 1;
        if (parent->height < 1) parent->height = 1;
    }
    return child;
}


void add_empty_link_list(link_t *link)
{
    if (head_empty)
    {
        link->next = head_empty->next;
    }
    head_empty = link;
}

/**
 * Description:
 * This function returns the first available link_t from the head_empty.
 * If head_empty is null, i.e. there is no link_t struct to return, then it mallocs
 * memory for one linkt_t.
 * It returns the link_t.
 *
 * Returns:
 * link_t *  a pointer to link_t that can be used.
 *
 */
link_t *get_link()
{
    link_t *link = NULL;
    
    if (head_empty)
    {
        link = head_empty;
        head_empty = head_empty->next;
    } else {
        link = (link_t *)malloc(sizeof(link_t));
        if (!link) {
            printf("CRITICAL ERROR: could not alloc memory for new link\n");
            exit(1);
        }
    }

    return link;
}

/**
 * Description:
 * This function returns a new bnode_t to be used as a node in a tree.
 * It gets the new bnode_t struct from the list pointed to by head. It gets the first link_t,
 * gets the bnode_t it is pointing to and returns the link_t to free it.
 * The bnode_t is the one to be returned to the calling function.
 * If the list head list is empty (head is NULL), it tries to obtain a new bnode_t from pre-allocated memory
 * referenced by the 2-dim array arrays_nodes at the last index specified by curr_array (indicating the current
 * 1-dim array).
 * If there is no more memory available, it initiates a process to reserve more memory for
 * new bnode_t structs.
 * This new memory is allocated for the next array of arrays_nodes, up to (MAX_ARRAYS - 1).
 * This is in order not to allocate memory for each bnode_t but for a big group of bnode_t's for the sake of performance.
 * If memory couldn't be allocated or it reached the MAX_ARRAYS number, it returns a NULL pointer.
 *
 * Returns:
 * bnode_t struct * if any available. Otherwise, NULL.
 *
 */
bnode_t *get_new_node()
{
    bnode_t *newnode;
    
    if (head)
    {
        link_t *auxlink = head;
        newnode = head->node;
        head = head->next;
        add_empty_link_list(auxlink);
    }
    else
    {
        if (arrays_indexes[curr_array] < MAX_NODES_IN_ARRAY)
        {
            newnode = &arrays_nodes[curr_array][arrays_indexes[curr_array]];
            arrays_indexes[curr_array]++;
        }
        else
        {
            if (curr_array < (MAX_ARRAYS - 1))
            {
                bnode_t *newarray = (bnode_t *) malloc(sizeof(bnode_t) * MAX_NODES_IN_ARRAY);
                
                if (newarray)
                {
                    curr_array++;
                    arrays_nodes[curr_array] = newarray;
                    newnode = &arrays_nodes[curr_array][0];
                    arrays_indexes[curr_array] = 1;
                    num_arrays++;
                }
                else
                {
                    newnode = NULL;
                }
            }
            else
            {
                newnode = NULL;
            }
        }
    }
    return newnode;
}

/**
 * Descripition:
 * This function is static. It's called to free a bnode_t that is not used in any tree.
 * The way to make it available is to add the bnode_t to the list pointed to by head.
 * In order to add the bnode_t we need a link_t struct. We get an available link_t struct from
 * function get_link. The link_t struct allows to add the bnode_t to the list.
 *
 * Parameters:
 * node     the bnode_t that is freed and doesn't belong to any tree.
 *
 */
void delete_node(bnode_t *node) {
    link_t *newlink;
    
    newlink = get_link();
        
    if (newlink) {
        newlink->node = node;
        if (head)
            newlink->next = head->next;
        else
            newlink->next = NULL;
        
        head = newlink;
    } else {
        printf("CRITICAL ERROR: could not get a new link for the freed node\n");
        exit(1);
    }
}

/**
 * Description:
 * This function frees all memory that has been allocated for binary trees.
 * After calling this function all binary tree functionality turns unusable and
 * calling any function may cause a segmentation fault.
 * To use this functionality again first init_binary_tree has to be called.
 */
void releaseAllBinaryTreeMemory() {
    for(uint32_t index = 1; index < num_arrays; index++) {
        if (arrays_nodes[index] != NULL) {
            free(arrays_nodes[index]);
            arrays_nodes[index] = NULL;
        }
    }
    link_t *link = head;
    while(link) {
        link_t *dellink = link;
        link = link->next;
        free(dellink);
    }
    link = head_empty;
    while(link) {
        link_t *dellink = link;
        link = link->next;
        free(dellink);
    }
    head = NULL;
    head_empty = NULL;
}
    


