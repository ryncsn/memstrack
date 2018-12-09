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


#define get_node_data(node, data_type, member)\
	(data_type*)((char *)node - offsetof(data_type, member))


struct TreeNode* get_tree_node(
		struct TreeNode **root_p,
		struct TreeNode *src,
		int (*comp)(struct TreeNode *src, struct TreeNode *root));


struct TreeNode* insert_tree_node(
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
