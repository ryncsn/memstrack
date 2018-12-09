#include <stddef.h>
#include "utils.h"

static int try_left_rotate(struct TreeNode **root) {
	struct TreeNode *right = (*root)->right;
	if (right == NULL) {
		return 1;
	}
	(*root)->right = right->left;
	right->left = (*root);
	*root = right;
	return 0;
}

static int try_right_rotate(struct TreeNode **root) {
	struct TreeNode *left = (*root)->left;
	if(left == NULL) {
		return 1;
	}
	(*root)->left = left->right;
	left->right = (*root);
	*root = left;
	return 0;
}

struct TreeNode* get_tree_node(
		struct TreeNode **root_p,
		struct TreeNode *src,
		int (*comp)(struct TreeNode *src, struct TreeNode *root))
{
	if (*root_p == NULL) {
		return NULL;
	}
	struct TreeNode **root = root_p;
	int result;
	while (*root) {
		result = comp(src, *root);
		if (result == 0) {
			return *root;
		} else if (result < 0 && (*root)->left) {
			result = comp(src, (*root)->left);
			try_right_rotate(root);
			if (result == 0) {
				return *root;
			} else if (result < 0) {
				root = &(*root)->left;
			} else {
				root = &(*root)->right;
			}
		} else if ((*root)->right) {
			result = comp(src, (*root)->right);
			try_left_rotate(root);
			if (result == 0) {
				return *root;
			} else if (result < 0) {
				root = &(*root)->right;
			} else {
				root = &(*root)->left;
			}
		} else {
			return NULL;
		}
	}
	return *root;
}

struct TreeNode* insert_tree_node(
		struct TreeNode **root_p,
		struct TreeNode *src,
		int (*comp)(struct TreeNode *src, struct TreeNode *root))
{
	if (*root_p == NULL) {
		return *root_p = src;
	} else {
		struct TreeNode *root = *root_p;
		int result = comp(src, root);
		if (result == 0) {
			return root;
		} else if (result < 0) {
			src->right = root;
			src->left = NULL;
		} else {
			src->left = root;
			src->right = NULL;
		}
		*root_p = src;
	}
	return src;
}

void iter_tree_node(
		struct TreeNode *root,
		void (*handler)(struct TreeNode *node, void *blob),
		void *blob
		)
{
	if (root == NULL) {
		return;
	}
	if (root->left) {
		iter_tree_node(root->left, handler, blob);
	}
	handler(root, blob);
	if (root->right) {
		iter_tree_node(root->right, handler, blob);
	}
}

struct HashNode* get_hash_node(
		struct HashMap* map,
		void *key)
{
	struct HashNode *node = map->buckets[map->hash(key) % HASH_BUCKET];
	while (node != NULL && map->comp(node->key, key) != 0) {
		node = node->next;
	}
	return node;
}

struct HashNode* insert_hash_node(
		struct HashMap* map,
		struct HashNode* src,
		void *key)
{
	struct HashNode **node = &(map->buckets[map->hash(key) % HASH_BUCKET]);
	src->next = *node;
	src->key = key;
	return *node = src;
}
