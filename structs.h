#include <stdio.h>
#include <stdlib.h>

// variables for iniFile's data
int request_packet_threshold;
int min_video_connection_size;
int inbound_packets_in_range_min;
int inbound_packets_in_range_max;
int max_number_of_connections;
int max_number_of_transaction_per_video;
int video_connection_timeout;


typedef struct node {
    void* data;
    struct node* next;
    struct node* prev;
} node;

const int SIZEOF_NODE = sizeof(node);

typedef struct list {
    node* head;
    node* tail;
    int size;
} list;

const int SIZEOF_LIST = sizeof(list);

typedef struct transaction
{
    double start_time;
    double end_time;
    int num_in_packets;
    int num_out_packets;
    int max_packet_size_in;
    int min_packet_size_in;
    double max_diff_time_in;
    double min_diff_time_in;
    double SumSquareInPacketTimeDiff;
    double RTT;
} transaction;

const int SIZEOF_TRANS = sizeof(transaction);
static int sum_all_trans = 0;

typedef struct five_tuple
{
    int client_ip_address;
    int server_ip_address;
    int udp_client_port;
} five_tuple;

const int SIZEOF_FIVET = sizeof(five_tuple);

typedef struct connection
{
    five_tuple *key;
    list *trans_list;
    double start_time;
    double end_time;
    long size;
} connection;

const int SIZEOF_CONN = sizeof(connection);
static int sum_all_conn = 0;

static inline transaction* create_trans(double epoch_time)
{
    transaction *trans = malloc(SIZEOF_TRANS);
    trans->start_time = trans->end_time = epoch_time;
    trans->num_out_packets = 0;
    trans->num_in_packets = 0;
    sum_all_trans++;
    return trans;
}

static inline connection* create_conn(double epoch_time, five_tuple *key)
{
    connection *conn = malloc(SIZEOF_CONN);
    conn->key = key;
    conn->size = 0;
    conn->start_time = conn->end_time = epoch_time;
    conn->trans_list = malloc(SIZEOF_LIST);
    transaction* trans = create_trans(epoch_time);
    node* trans_node = malloc(SIZEOF_NODE);
    trans_node->data = trans;
    trans_node->next = trans_node->prev = NULL;
    conn->trans_list->head = trans_node;
    conn->trans_list->tail = trans_node;
    conn->trans_list->size = 1;
    sum_all_conn++;
    return conn;
}

static inline list* create_list()
{
    list *l = malloc(SIZEOF_LIST);
    l->size = 0;
    l->head = l->tail = NULL;
    return l;
}

static inline void push_back(list* l, void* data)
{
    node* n = malloc(SIZEOF_NODE);
    n->data = data;
    n->next = NULL;
    if (l->size == 0)
    {
        l->head = n;
        l->tail = n;
        n->prev = NULL;
    }
    else
    {
        n->prev = l->tail;
        l->tail->next = n;
        l->tail = n;
    }
    l->size++;
}

static inline void push_front(list* l, void* data) {
    if (l == NULL)
    {
        return;
    }
    node* n = malloc(SIZEOF_NODE);
    n->data = data;
    n->prev = NULL;
    if (l->size == 0)
    {
        n->next = NULL;
        l->head = l->tail = n;
    }
    else
    {
        l->head->prev = n;
        n->next = l->head;
        l->head = n;
    }
    l->size++;
}

static inline void* pop_back(list* l) {
    
    if (l == NULL || l->size == 0)
    {
        return NULL;
    }
    void* data = l->tail->data;
    l->tail = l->tail->prev;
    if (l->size == 1)
    {
        l->head = NULL;
    }
    else
    {
        l->tail->next = NULL;
        free(l->tail->next);
    }
    l->size--;
    return data;
}

static inline void* pop_front(list* l) {
    if (l == NULL || l->size == 0)
    {
        return NULL;
    }
    void *data = l->head->data;
    l->head = l->head->next;
    if (l->size == 1)
    {
        l->tail = NULL;
    }
    else
    {
        l->head->prev = NULL;
        free(l->head->prev);
    }
    l->size--;
    return data;
}

static inline int equal(five_tuple *key1, five_tuple *key2)
{
    return key1->udp_client_port == key2->udp_client_port && key1->server_ip_address == key2->server_ip_address && key1->client_ip_address == key2->client_ip_address;
}

static inline node* find_conn_in_list(list* l, five_tuple* key)
{
    if (l == NULL)
    {
        return NULL;
    }
    node *n = l->head;
    while (n != NULL && !equal(((connection*)n->data)->key, key))
    {
        n = n->next;
    }
    return n;
}

static inline void delete_from_list(list* l, node* n)
{
    if (l == NULL || l->size == 0)
    {
        return;
    }
    if (n == l->tail)
    {
        pop_back(l);
    }
    else if (n == l->head)
    {
        pop_front(l);
    }
    else
    {
        node* next = n->next;
        node* prev = n->prev;
        next->prev = prev;
        prev->next = next;
        free(n);
        l->size--;
    }
}

