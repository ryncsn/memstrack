#ifndef _MEMORY_TRACER_UTILS
#define _MEMORY_TRACER_UTILS 1

#define HASH_BUCKET 1024

struct TreeNode {
	struct TreeNode* left;
	struct TreeNode* right;
};

typedef int (TreeComp)(struct TreeNode *node, const void *key);

struct HashNode {
	void* blob;
	struct HashNode *next;
};

typedef unsigned int (HashOp)(const void *blob);
typedef unsigned int (HashComp)(const void *lblob, const void *key);

struct HashMap {
	HashOp *hash;
	HashComp *comp;

	struct HashNode *buckets[HASH_BUCKET];
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


struct HashNode* get_hash_node(
		struct HashMap* map,
		void *key);


struct HashNode* insert_hash_node(
		struct HashMap* map,
		struct HashNode* src,
		void *key);

#endif /* ifndef _MEMORY_TRACER_UTILS */
