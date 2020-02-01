#ifndef _MEMORY_TRACER_UTILS
#define _MEMORY_TRACER_UTILS 1
#define HASH_BUCKET 1024


struct TreeNode {
	struct TreeNode* left;
	struct TreeNode* right;
};


struct HashNode {
	void* key;
	struct HashNode *next;
};


struct HashMap {
	int (*hash)(const void *key);
	int (*comp)(const void *lhk, const void* rhk);

	struct HashNode *buckets[HASH_BUCKET];
};


#define container_of(ptr, type, member)\
	((type *)((void *)(ptr) - offsetof(type, member)))


#define have_left_child(ptr, type, member)\
	((((struct TreeNode*)((void *)(ptr) + offsetof(type, member)))->left) != NULL)


#define left_child(ptr, type, member)\
	container_of((((struct TreeNode*)((void *)(ptr) + offsetof(type, member)))->left), type, member)


#define have_right_child(ptr, type, member)\
	((((struct TreeNode*)((void *)(ptr) + offsetof(type, member)))->right) != NULL)


#define right_child(ptr, type, member)\
	container_of((((struct TreeNode*)((void *)(ptr) + offsetof(type, member)))->right), type, member)


struct TreeNode* get_tree_node(
		struct TreeNode **root_p,
		struct TreeNode *src,
		int (*comp)(struct TreeNode *src, struct TreeNode *root));


struct TreeNode* get_remove_tree_node(
		struct TreeNode **root_p,
		struct TreeNode *src,
		int (*comp)(struct TreeNode *src, struct TreeNode *root));


void insert_tree_node(
		struct TreeNode **root_p,
		struct TreeNode *src,
		int (*comp)(struct TreeNode *src, struct TreeNode *root));

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
