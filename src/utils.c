/*
 * utils.c
 *
 * Copyright (C) 2020 Red Hat, Inc., Kairui Song <kasong@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include<stdio.h>
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

static struct TreeNode* remove_tree_node(struct TreeNode **root) {
	struct TreeNode *ret;
	while (1) {
		if ((*root)->left == NULL) {
			ret = *root;
			*root = (*root)->right;
			return ret;
		} else if ((*root)->right == NULL) {
			ret = *root;
			*root = (*root)->left;
			return ret;
		} else {
			try_right_rotate(root);
			root = &(*root)->right;
		}
	}
}

static int get_tree_depth(struct TreeNode *root) {
	int max_depth = 1, depth = 1;
	if (root->left) {
		depth += get_tree_depth(root->left);
		if (depth > max_depth) {
			max_depth = depth;
		}
	}
	if (root->right) {
		depth += get_tree_depth(root->right);
		if (depth > max_depth) {
			max_depth = depth;
		}
	}
	return max_depth;
}

struct TreeNode* get_tree_node(
		struct TreeNode **root, void *key,
		TreeComp comp)
{
	int result;
	while (*root) {
		result = comp(*root, key);
		if (result == 0) {
			return *root;
		} else if (result < 0) {
			if (!(*root)->left) {
				return NULL;
			}
			result = comp((*root)->left, key);
			try_right_rotate(root);
			if (result == 0) {
				return *root;
			} else if (result < 0) {
				root = &(*root)->left;
			} else {
				root = &(*root)->right->left;
			}
		} else {
			if (!(*root)->right) {
				return NULL;
			}
			result = comp((*root)->right, key);
			try_left_rotate(root);
			if (result == 0) {
				return *root;
			} else if (result > 0) {
				root = &(*root)->right;
			} else {
				root = &(*root)->left->right;
			}
		}
	}
	return NULL;
}

struct TreeNode* get_remove_tree_node(
		struct TreeNode **root, void *key,
		TreeComp comp)
{
	int result;
	while (*root) {
		result = comp(*root, key);
		if (result == 0) {
			return remove_tree_node(root);
		} else if (result < 0) {
			if (!(*root)->left) {
				return NULL;
			}
			result = comp((*root)->left, key);
			try_right_rotate(root);
			if (result == 0) {
				return remove_tree_node(root);
			} else if (result < 0) {
				root = &(*root)->left;
			} else {
				root = &(*root)->right->left;
			}
		} else {
			if (!(*root)->right) {
				return NULL;
			}
			result = comp((*root)->right, key);
			try_left_rotate(root);
			if (result == 0) {
				return remove_tree_node(root);
			} else if (result > 0) {
				root = &(*root)->right;
			} else {
				root = &(*root)->left->right;
			}
		}
	}
	return NULL;
}

void insert_tree_node(
		struct TreeNode **root_p, struct TreeNode *src, void *key,
		TreeComp comp)
{
	struct TreeNode *root = *root_p;
	int result;

	if (root == NULL)
		*root_p = src;

	while (1) {
		result = comp(root, key);
		if (result == 0) {
			return;
		} else if (result < 0) {
			if (root->left) {
				root = root->left;
			} else {
				root->left = src;
			}
		} else {
			if (root->right) {
				root = root->right;
			} else {
				root->right = src;
			}
		}
	}
}

/*
 * DFS starts from left
 */
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
	while (node != NULL && map->comp(node, key) != 0) {
		node = node->next;
	}
	return node;
}

void insert_hash_node(
		struct HashMap* map,
		struct HashNode* src,
		void *key)
{
	struct HashNode **node = &(map->buckets[map->hash(key) % HASH_BUCKET]);
	src->next = *node;
	*node = src;
	map->size ++;
}
