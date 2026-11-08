#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netfilter/gta3xlwifi_local_network.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define LNA_NONE (-1)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
struct lna_node {
    u8 key[GTA3XLWIFI_LNA_KEY_BYTES];
    u16 bits;
    u8 has_value, value;
    int child[2];
};
struct lna_table {
    u32 count, nodes_count;
    int root;
    struct gta3xlwifi_lna_entry *entries;
    struct lna_node *nodes;
};
static bool lna_prefix(const u8 *a, const u8 *b, u32 bits)
{
    u32 bytes = bits / 8, remainder = bits % 8;
    return !memcmp(a, b, bytes) &&
        (!remainder || !((a[bytes] ^ b[bytes]) & (0xffU << (8 - remainder))));
}
static unsigned int lna_bit(const u8 *key, unsigned int bit)
{
    return (key[bit / 8] >> (7 - bit % 8)) & 1;
}
static void lna_canonical(u8 *key, u32 bits)
{
    u32 bytes = bits / 8;
    if (bits % 8) {
        key[bytes] &= 0xffU << (8 - bits % 8);
        ++bytes;
    }
    memset(key + bytes, 0, GTA3XLWIFI_LNA_KEY_BYTES - bytes);
}
static int lna_node_new(struct lna_table *table, const u8 *key, u32 bits,
                        bool has_value, bool value)
{
    struct lna_node *node;
    int index;
    if (table->nodes_count >= 2 * table->count)
        return -E2BIG;
    index = table->nodes_count++;
    node = &table->nodes[index];
    memcpy(node->key, key, sizeof(node->key));
    lna_canonical(node->key, bits);
    node->bits = bits;
    node->has_value = has_value;
    node->value = value;
    node->child[0] = node->child[1] = LNA_NONE;
    return index;
}
static int lna_insert(struct lna_table *table, const struct gta3xlwifi_lna_entry *entry)
{
    int *link = &table->root;
    while (*link != LNA_NONE) {
        struct lna_node *node = &table->nodes[*link];
        u32 common = 0, limit = min_t(u32, node->bits, entry->prefix_bits);
        int branch, leaf, previous = *link;
        while (common < limit && lna_bit(node->key, common) == lna_bit(entry->key, common))
            ++common;
        if (common < node->bits) {
            branch = lna_node_new(table, entry->key, common,
                                   common == entry->prefix_bits, entry->allowed);
            if (branch < 0)
                return branch;
            table->nodes[branch].child[lna_bit(node->key, common)] = previous;
            if (common < entry->prefix_bits) {
                leaf = lna_node_new(table, entry->key, entry->prefix_bits, true, entry->allowed);
                if (leaf < 0)
                    return leaf;
                table->nodes[branch].child[lna_bit(entry->key, common)] = leaf;
            }
            *link = branch;
            return 0;
        }
        if (common == entry->prefix_bits) {
            if (node->has_value)
                return -EINVAL;
            node->has_value = true;
            node->value = entry->allowed;
            return 0;
        }
        link = &node->child[lna_bit(entry->key, node->bits)];
    }
    *link = lna_node_new(table, entry->key, entry->prefix_bits, true, entry->allowed);
    return *link < 0 ? *link : 0;
}
static bool lna_lookup(const struct lna_table *table, const u8 *key, bool *value)
{
    int index = table->root;
    bool found = false;
    while (index != LNA_NONE) {
        const struct lna_node *node = &table->nodes[index];
        if (!lna_prefix(node->key, key, node->bits))
            break;
        if (node->has_value) {
            *value = node->value;
            found = true;
        }
        if (node->bits == GTA3XLWIFI_LNA_KEY_BITS)
            break;
        index = node->child[lna_bit(key, node->bits)];
    }
    return found;
}
static struct lna_table table;
void oracle_clear(void){free(table.nodes);memset(&table,0,sizeof(table));table.root=-1;}
int oracle_set(const struct gta3xlwifi_lna_entry*entries,unsigned count){oracle_clear();table.count=count;table.nodes=calloc(2*count,sizeof(*table.nodes));if(count&&!table.nodes)return -ENOMEM;for(unsigned i=0;i<count;i++){int r=lna_insert(&table,entries+i);if(r)return r;}return 0;}
int oracle_lookup(const unsigned char*key,bool*value){return lna_lookup(&table,key,value);}
void oracle_canonical(unsigned char*key,unsigned bits){lna_canonical(key,bits);}
