#include <stddef.h>
#include "utils.h"

struct TreeNode* get_tree_node(
		struct TreeNode **root_p,
		struct TreeNode *src,
		int (*comp)(struct TreeNode *src, struct TreeNode *root))
{
	if (*root_p == NULL) {
		return NULL;
	}
	struct TreeNode *root = *root_p;
	while (root) {
		int result = comp(src, root);
		if (result == 0) {
			return root;
		} else if (result < 0) {
			root = root->left;
		} else {
			root = root->right;
		}
	}
	return root;
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
