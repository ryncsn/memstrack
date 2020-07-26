/*
 * utils.h
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

#ifndef _MEMORY_TRACER_UTILS
#define _MEMORY_TRACER_UTILS 1

#define HASH_BUCKET 1024

struct TreeNode {
	struct TreeNode* left;
	struct TreeNode* right;
};

typedef int (TreeComp)(const struct TreeNode *node, const void *key);

struct HashNode {
	struct HashNode *next;
};

typedef unsigned int (HashOp)(const void *key);
typedef unsigned int (HashComp)(const struct HashNode *blob, const void *key);

struct HashMap {
	int size;
	HashOp *hash;
	HashComp *comp;

	struct HashNode *buckets[HASH_BUCKET];
};

#define HASH_MAP(hash, comp, name)\
	struct HashMap name = {\
		0, hash, comp, {NULL}\
	};

#define for_each_hnode(hashmap_p, hnode)\
	for (int _bucket = 0; _bucket < HASH_BUCKET; _bucket++)\
	for (hnode = (hashmap_p)->buckets[_bucket]; hnode != NULL; hnode = hnode->next)

#define container_of(ptr, type, member)\
	((type *)((void *)(ptr) - offsetof(type, member)))

#define have_left_child(ptr, member)\
	!!(ptr)->member.left

#define left_child(ptr, type, member)\
	container_of(((ptr)->member.left), type, member)

#define have_right_child(ptr, member)\
	!!(ptr)->member.right

#define right_child(ptr, type, member)\
	container_of(((ptr)->member.right), type, member)

struct TreeNode* get_tree_node(
		struct TreeNode **root_p, void *key,
		TreeComp comp);

struct TreeNode* get_remove_tree_node(
		struct TreeNode **root_p, void *key,
		TreeComp comp);

void insert_tree_node(
		struct TreeNode **root_p, struct TreeNode *src, void *key,
		TreeComp comp);

void iter_tree_node(
		struct TreeNode *root,
		void (*handler)(struct TreeNode *node, void *blob),
		void *blob);

struct HashNode* get_remove_hash_node(
		struct HashMap* map,
		void *key);

struct HashNode* get_hash_node(
		struct HashMap* map,
		void *key);

void insert_hash_node(
		struct HashMap* map,
		struct HashNode* src,
		void *key);

#endif /* ifndef _MEMORY_TRACER_UTILS */
