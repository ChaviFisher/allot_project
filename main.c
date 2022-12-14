#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <pcap.h>
#include <time.h>
#include "structs.h"

#define YOUTUBE_PORT 443
#define HASH_TABLE_SIZE 1000

// variables for iniFile's data
int request_packet_threshold;
int min_video_connection_size;
int inbound_packets_in_range_min;
int inbound_packets_in_range_max;
int max_number_of_connections;
int max_number_of_transaction_per_video;
int video_connection_timeout;

// global resources
static list *hash_table[HASH_TABLE_SIZE] = {NULL};
static FILE *csvfile;
static list *hash_used_places;
static const int SIZEOF_ETHHDR = sizeof(struct ethhdr);
static const int SIZEOF_IPHDR = sizeof(struct iphdr);
static const int SIZEOF_UDPHDR = sizeof(struct udphdr);

int put_ini_data();
int write_videos_statistics();
static inline void req_packets_handle(uint, uint, double, tuples *);
static inline void inbound_packets_handle(uint, uint, uint, double, tuples *);
static inline void small_out_packets_handle(uint, double, tuples *);
static inline tuples *create_key_of_3_tuple(int, int, int);
static inline void write_connection_into_csv(connection *);

// variables for videos statistics
static int sum_conn = 0;
static double average_duration_of_the_videos = 0;
static double average_size_of_the_videos = 0;
static double average_number_of_TDRs_per_video = 0;
static double average_size_of_the_TDRs_per_video = 0;
static double average_duration_of_the_TDRs_per_video = 0;
static double average_time_between_two_consecutive_TDRs = 0;

int main(int argc, char **argv)
{

    // for the files
    char *errbuf = 0;

    // put the data from ini file in the variables
    if (put_ini_data() == -1)
    {
        printf("Unable to open ini file.\n");
        return 1;
    }

    // open csv file
    csvfile = fopen("statistic.csv", "w+");
    if (csvfile == NULL)
    {
        printf("Unable to open csv file.\n");
        return 1;
    }
    fprintf(csvfile, "Conn_id, Client_IP, Server_IP, IP_protocol,"
                     "UDP_client_port, UDP_server_port, Transaction_id,"
                     "Start time, num_in_packets, num_out_packets,"
                     "max_packet_size_in, min_packet_size_in,"
                     "max_diff_time_in, min_diff_time_in,  RTT\n");

    // open pcap file
    struct pcap *pcapfile = pcap_open_offline("pcap_file.pcap", errbuf);
    if (pcapfile == NULL)
    {
        fprintf(stderr, "pcap_open_offline() failed: %s\n", errbuf);
        return 1;
    }

    // intialize hash_used_place list
    hash_used_places = create_list();

    struct pcap_pkthdr *pkthdr;
    const u_char *packet;

    // beyond on the packets
    while (pcap_next_ex(pcapfile, &pkthdr, &packet) >= 0 && sum_conn < max_number_of_connections)
    {
        struct iphdr *ipHeader = (struct iphdr *)(packet + SIZEOF_ETHHDR);

        if (ipHeader->protocol != IPPROTO_UDP)
        {
            continue;
        }

        struct udphdr *udpHeader = (struct udphdr *)(packet + SIZEOF_ETHHDR + (ipHeader->ihl << 2));
        u_int sourcePort = ntohs(udpHeader->source);
        u_int destPort = ntohs(udpHeader->dest);

        uint packet_size = pkthdr->len - SIZEOF_ETHHDR - SIZEOF_IPHDR - SIZEOF_UDPHDR;

        // if the packet is not for youtube and not from youtube and in the range
        if (destPort != YOUTUBE_PORT && (sourcePort != YOUTUBE_PORT ||
                                         packet_size < inbound_packets_in_range_min ||
                                         packet_size > inbound_packets_in_range_max))
        {
            continue;
        }

        uint src_ip = ntohs(ipHeader->saddr);
        uint dest_ip = ntohs(ipHeader->daddr);
        double epoch_time = pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000;

        if (sourcePort == YOUTUBE_PORT)
        {                                        // if it is inbound packet
            tuples *key = create_key_of_3_tuple( // create the key by the dest address and dest port for the client data, and the src address for the server address.
                ipHeader->daddr, ipHeader->saddr, destPort);
            uint hash_index = (src_ip + dest_ip + destPort) % HASH_TABLE_SIZE;          // get the hash_index by the key's tuples.
            inbound_packets_handle(hash_index, packet_size, destPort, epoch_time, key); // handle it in inbound-packets handler
        }
        else
        {                                        // else, it is outbound packet, so:
            tuples *key = create_key_of_3_tuple( // create the key by the src address and src port for the client data, and the dest address for the server address.
                ipHeader->saddr, ipHeader->daddr, sourcePort);
            uint hash_index = (src_ip + dest_ip + sourcePort) % HASH_TABLE_SIZE; // get the hash_index by the key's tuples.
            if (packet_size >= request_packet_threshold)
            { // if it is request packet, handle it in request-packets handler
                req_packets_handle(hash_index, sourcePort, epoch_time, key);
            }
            else
            { // else it is a small outbound packet, handle in his handler.
                small_out_packets_handle(hash_index, epoch_time, key);
            }
        }
    }

    // release and write the connections that remain in the table
    while (hash_used_places->size > 0)
    {
        list *conn_list = (list *)pop_front(hash_used_places);
        while (conn_list->size > 0)
        {
            connection *conn = (connection *)pop_back(conn_list);
            if (conn->size >= min_video_connection_size)
            {
                write_connection_into_csv(conn);
            }
        }
    }

    // close files
    pcap_close(pcapfile);
    fclose(csvfile);

    // (complete to) compute and write videos statistics
    if (write_videos_statistics() == -1)
    {
        printf("Unable to open csv file for videos statistics.\n");
        return 1;
    }

    // free reachables
    free(hash_used_places);
    free(errbuf);

    return 0;
}

// this function handles the request packets.
// if the matched place in the hash table does not contain connections list,
// it creates new list with new connection and one transaction, and put it there.
// else it searchs in the list a connection with the tuples of the packet,
// if not found - creates new connection (include new transaction) and pushes to the list.
// else, inserts new transaction to the connection's transactions list.
static inline void req_packets_handle(uint hash_index, uint sourcePort, double epoch_time, tuples *key)
{
    list *conn_list = hash_table[hash_index];
    if (conn_list == NULL && sum_all_conn < max_number_of_connections)
    {
        conn_list = malloc(SIZEOF_LIST);
        node *conn_node = malloc(SIZEOF_NODE);
        connection *conn = create_conn(epoch_time, key);
        conn_node->data = conn;
        conn_node->next = conn_node->prev = NULL;
        conn_list->head = conn_list->tail = conn_node;
        conn_list->size = 1;
        hash_table[hash_index] = conn_list;
        // since a new cell in the table is now used, add it to the used pleaces's list
        push_back(hash_used_places, conn_list);
    }
    else
    {
        node *conn_node = find_conn_in_list(conn_list, key);
        if (conn_node == NULL)
        { // if there is no such connection
            if (sum_all_conn < max_number_of_connections)
            { // if can still create more one
                connection *conn = create_conn(epoch_time, key);
                push_front(conn_list, conn);
            }
        }
        else
        { // else, there is the connection
            connection *conn = (connection *)conn_node->data;
            if (conn->trans_list->size >= max_number_of_transaction_per_video)
            { // if the connection is closed bacuse it has reached the allowed packet limit
                if (conn->size >= min_video_connection_size)
                { // if his size meets video requirements, write him into csv file
                    write_connection_into_csv(conn);
                }
                delete_from_list(conn_list, conn_node);

                if (sum_all_conn < max_number_of_connections)
                { // if can still create more one
                    connection *conn = create_conn(epoch_time, key);
                    push_front(conn_list, conn);
                }
            }
            else
            { // else, the connection is not closed, so add him new transaction
                transaction *trans = create_trans(epoch_time);
                push_front(conn->trans_list, trans);
                conn->end_time = epoch_time;
            }
        }
    }
}

// this function handles the inbound packets.
// it checks if exists connection with the packet's tuples, with help of the hash table,
// if exit checks if the connection closed due to the timeout or number of transactions.
// if closed write the connection into csvfile, delete it from the list, and ignore the packet.
// else update the connection and his last transaction matching to the packet.
// if connection not exists, ignore the packet.
static inline void inbound_packets_handle(uint hash_index, uint packet_size, uint destPort, double epoch_time, tuples *key)
{
    list *conn_list = hash_table[hash_index];
    node *conn_node = find_conn_in_list(conn_list, key);
    if (conn_node == NULL)
    { // if there is no such connection
        return;
    }
    connection *conn = (connection *)conn_node->data;
    if (epoch_time - conn->end_time > video_connection_timeout)
    { // if the connection is closed because the timeout
        if (conn->size >= min_video_connection_size)
        { // if if his size meets video requirements, write him into csv file
            write_connection_into_csv(conn);
        }
        delete_from_list(conn_list, conn_node);
        return;
    }
    // go to tha last transaction of this connection, and update her data
    conn->size += packet_size;
    node *trans_node = conn->trans_list->head;
    transaction *trans = (transaction *)trans_node->data;
    double diff = epoch_time - conn->end_time;
    conn->end_time = trans->end_time = epoch_time;
    trans->num_in_packets++;
    if (trans->num_in_packets == 1)
    { // if it is the first inbound packet in this transaction
        trans->RTT = diff;
        trans->min_packet_size_in = packet_size;
        trans->max_packet_size_in = packet_size;
        return;
    }
    if (trans->min_packet_size_in > packet_size)
    {
        trans->min_packet_size_in = packet_size;
    }
    else if (trans->max_packet_size_in < packet_size)
    {
        trans->max_packet_size_in = packet_size;
    }
    if (trans->num_in_packets == 2)
    { // if it is the second inbound packet in this transaction
        trans->min_diff_time_in = diff;
        trans->max_diff_time_in = diff;
    }
    else
    {
        if (trans->min_diff_time_in > diff)
        {
            trans->min_diff_time_in = diff;
        }
        else if (trans->max_diff_time_in < diff)
        {
            trans->max_diff_time_in = diff;
        }
    }
}

// this function handles the small outbound packets.
// it finds the connection who has the tuples of the packet, if exists,
// and updates his end_time and num_out_packets of his last transaction.
static inline void small_out_packets_handle(uint hash_index, double epoch_time, tuples *key)
{
    list *conn_list = hash_table[hash_index];
    node *conn_node = find_conn_in_list(conn_list, key);
    if (conn_node != NULL)
    { // if there is such connection, update his last transaction and his end_time
        connection *conn = (connection *)conn_node->data;
        node *trans_node = conn->trans_list->head;
        transaction *trans = (transaction *)trans_node->data;
        trans->num_out_packets++;
        conn->end_time = epoch_time;
    }
}

// this function gets the unique tuples of youtube packet,
// creates a struct that contains them and returns his pointer.
static inline tuples *create_key_of_3_tuple(int client_ip, int server_ip, int clientPort)
{
    tuples *ft = malloc(SIZEOF_TUPLES);
    ft->client_ip_address = client_ip;
    ft->server_ip_address = server_ip;
    ft->udp_client_port = clientPort;
    return ft;
}

// this function gets connection and write every one from his transactions into the csvfile.
// durring the writing it also updates some video-statistics variables.
// in addition, it release every transaction after the writing,
// and in the final also their list and connection.
static inline void write_connection_into_csv(connection *conn)
{
    int trans_id = 0;
    list *trans_list = conn->trans_list;
    node *trans_node = trans_list->tail;

    // for videos statistics
    average_duration_of_the_videos += conn->end_time - conn->start_time;
    average_size_of_the_videos += conn->size;
    average_number_of_TDRs_per_video += trans_list->size;
    double prev_time = conn->start_time;

    // for a pretty format for the addresses
    struct in_addr addr;
    addr.s_addr = conn->key->server_ip_address;
    char server_addr[100];
    strcpy(server_addr, inet_ntoa(addr));
    addr.s_addr = conn->key->client_ip_address;

    while (trans_node != NULL)
    {
        transaction *trans = (transaction *)trans_node->data;

        average_duration_of_the_TDRs_per_video += trans->end_time - trans->start_time;
        average_time_between_two_consecutive_TDRs += trans->start_time - prev_time;
        prev_time = trans->end_time;

        // for a pretty format for the start time
        time_t packet_time = trans->start_time;
        struct tm *tmp = localtime(&packet_time);

        fprintf(csvfile, "%d, %s, %s, %d, %d, %d, %d, "
                         "%d:%d:%d, %d, %d, %d, %d, %lf, %lf, %lf\n",
                sum_conn, server_addr, inet_ntoa(addr), IPPROTO_UDP,
                conn->key->udp_client_port, YOUTUBE_PORT,
                trans_id++, tmp->tm_hour, tmp->tm_min, tmp->tm_sec,
                trans->num_in_packets, trans->num_out_packets,
                trans->max_packet_size_in, trans->min_packet_size_in,
                trans->max_diff_time_in, trans->min_diff_time_in, trans->RTT);

        free(trans);
        node *prev = trans_node->prev;
        free(trans_node);
        trans_node = prev;
    }

    sum_conn++;
    free(trans_list);
    free(conn);
}

// this function extracts the information data from json file,
// and saves them in the local variables.
int put_ini_data()
{
    char buffer[PCAP_BUF_SIZE];

    // open and read json file to buffer
    FILE *inifile = fopen("ini.json", "r");
    if (inifile == NULL)
    {
        return -1;
    }
    fread(buffer, PCAP_BUF_SIZE, 1, inifile);
    fclose(inifile);

    // parse data from buffer to json object
    struct json_object *parsed_j;
    parsed_j = json_tokener_parse(buffer);

    // extracting the values from json object and put them into local variables
    struct json_object *jrequest_packet_threshold;
    struct json_object *jmin_video_connection_size;
    struct json_object *jinbound_packets_in_range_min;
    struct json_object *jinbound_packets_in_range_max;
    struct json_object *jmax_number_of_connections;
    struct json_object *jmax_number_of_transaction_per_video;
    struct json_object *jvideo_connection_timeout;
    json_object_object_get_ex(parsed_j, "request_packet_threshold", &jrequest_packet_threshold);
    json_object_object_get_ex(parsed_j, "min_video_connection_size", &jmin_video_connection_size);
    json_object_object_get_ex(parsed_j, "inbound_packets_in_range_min", &jinbound_packets_in_range_min);
    json_object_object_get_ex(parsed_j, "inbound_packets_in_range_max", &jinbound_packets_in_range_max);
    json_object_object_get_ex(parsed_j, "max_number_of_connections", &jmax_number_of_connections);
    json_object_object_get_ex(parsed_j, "max_number_of_transaction_per_video", &jmax_number_of_transaction_per_video);
    json_object_object_get_ex(parsed_j, "video_connection_timeout", &jvideo_connection_timeout);
    request_packet_threshold = json_object_get_int(jrequest_packet_threshold);
    min_video_connection_size = json_object_get_int(jmin_video_connection_size);
    inbound_packets_in_range_min = json_object_get_int(jinbound_packets_in_range_min);
    inbound_packets_in_range_max = json_object_get_int(jinbound_packets_in_range_max);
    max_number_of_connections = json_object_get_int(jmax_number_of_connections);
    max_number_of_transaction_per_video = json_object_get_int(jmax_number_of_transaction_per_video);
    video_connection_timeout = json_object_get_int(jvideo_connection_timeout);

    return 0;
}

// this function completes the computment the videos statistics
// and writes the results into csv file.
int write_videos_statistics()
{
    int sum_TDRs_per_videos = average_number_of_TDRs_per_video;
    average_duration_of_the_TDRs_per_video /= sum_TDRs_per_videos;
    average_time_between_two_consecutive_TDRs /= (sum_TDRs_per_videos - sum_conn);
    average_duration_of_the_videos /= sum_conn;
    average_size_of_the_videos /= sum_conn;
    average_number_of_TDRs_per_video /= sum_conn;
    average_size_of_the_TDRs_per_video = average_size_of_the_videos / average_number_of_TDRs_per_video;

    // write to video scv file
    csvfile = fopen("videos_statistic.csv", "w+");
    if (csvfile == NULL)
    {
        return -1;
    }
    fprintf(csvfile, "statistic description, statistic result\n");
    fprintf(csvfile, "How many videos connections have been watched, %d\n", sum_conn);
    fprintf(csvfile, "Average duration of the videos, %lf\n", average_duration_of_the_videos);
    fprintf(csvfile, "Average size of the videos, %lf\n", average_size_of_the_videos);
    fprintf(csvfile, "Average number of TDRs per video, %lf\n", average_number_of_TDRs_per_video);
    fprintf(csvfile, "Average size of the TDRs per video, %lf\n", average_size_of_the_TDRs_per_video);
    fprintf(csvfile, "Average duration of the TDRs per video, %lf\n", average_duration_of_the_TDRs_per_video);
    fprintf(csvfile, "Average time between two consecutive TDRs in a video, %lf\n", average_time_between_two_consecutive_TDRs);

    fclose(csvfile);

    // print for visualic fidback
    printf("How many videos connections have been watched: %d\n", sum_conn);
    printf("Average duration of the videos: %lf\n", average_duration_of_the_videos);
    printf("Average size of the videos: %lf\n", average_size_of_the_videos);
    printf("Average number of TDRs per video: %lf\n", average_number_of_TDRs_per_video);
    printf("Average size of the TDRs per video: %lf\n", average_size_of_the_TDRs_per_video);
    printf("Average duration of the TDRs per video: %lf\n", average_duration_of_the_TDRs_per_video);
    printf("Average time between two consecutive TDRs in a video: %lf\n", average_time_between_two_consecutive_TDRs);
    printf("\ncompleted succesfuly. sum all conn: %d. sum all trans: %d.\n", sum_all_conn, sum_all_trans);

    return 0;
}
