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

static list **hash_table;
static FILE *csvfile;
static list *hash_used_places;
static const int SIZEOF_ETHHDR = sizeof(struct ethhdr);
static const int SIZEOF_IPHDR = sizeof(struct iphdr);
static const int SIZEOF_UDPHDR = sizeof(struct udphdr);

int put_ini_data();
int write_videos_statistics();
static inline void req_packets_handle(uint, uint, double, five_tuple*);
static inline void in_packets_handle(uint, uint, uint, double, five_tuple*);
static inline void small_out_packets_handle(uint, double, five_tuple*);
static inline five_tuple *create_key_of_5_tuple(int, int, int);
static inline void write_connection_into_csv(connection *);

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
                     "UDP_client_port, UDP_server_port, Transaction_id, Start time,"
                     "num_in_packets, num_out_packets, max_packet_size_in, "
                     "min_packet_size_in, max_diff_time_in, min_diff_time_in, "
                     "SumSquareInPacketTimeDiff, RTT\n");

    // open pcap file
    struct pcap *pcapfile = pcap_open_offline("pcap_file.pcap", errbuf);
    if (pcapfile == NULL)
    {
        fprintf(stderr, "pcap_open_offline() failed: %s\n", errbuf);
        return 1;
    }

    hash_table = malloc(max_number_of_connections * sizeof(list*));
    hash_used_places = create_list();

    struct pcap_pkthdr *pkthdr;
    const u_char *packet;

    // beyond on the packets
    while (pcap_next_ex(pcapfile, &pkthdr, &packet) >= 0)
    {
        struct iphdr *ipHeader = (struct iphdr *)(packet + SIZEOF_ETHHDR);

        if (ipHeader->protocol != IPPROTO_UDP)
        {
            continue;
        }

        struct udphdr *udpHeader = (struct udphdr *)(packet + SIZEOF_ETHHDR + (ipHeader->ihl << 2));
        u_int sourcePort = ntohs(udpHeader->source);
        u_int destPort = ntohs(udpHeader->dest);
        uint size = pkthdr->len - SIZEOF_ETHHDR - SIZEOF_IPHDR - SIZEOF_UDPHDR;

        if (destPort != YOUTUBE_PORT && (sourcePort != YOUTUBE_PORT || 
            size < inbound_packets_in_range_min || 
            size > inbound_packets_in_range_max)
            )
        {
            continue;
        }

        uint src_ip = ntohs(ipHeader->saddr);
        uint dest_ip = ntohs(ipHeader->daddr);
        double epoch_time = pkthdr->ts.tv_sec + (double)pkthdr->ts.tv_usec / 1000000;

        if (sourcePort == YOUTUBE_PORT)
        {
            five_tuple *key = create_key_of_5_tuple(
                ipHeader->daddr, ipHeader->saddr, destPort);
            uint hash_index = (src_ip + dest_ip + destPort) % max_number_of_connections;
            in_packets_handle(hash_index, size, destPort, epoch_time, key);
        }
        else
        {
            five_tuple *key = create_key_of_5_tuple(
                ipHeader->saddr, ipHeader->daddr, sourcePort);
            uint hash_index = (src_ip + dest_ip + sourcePort) % max_number_of_connections;
            if (size >= request_packet_threshold)
            {
                req_packets_handle(hash_index, sourcePort, epoch_time, key);
            }
            else
            {
                small_out_packets_handle(hash_index, epoch_time, key);
            }
        }
    }

    // release and write the connections that remain in the table 
    while (hash_used_places->size > 0)
    {
        list *conn_list = (list*)pop_front(hash_used_places);
        while (conn_list->size > 0)
        {
            connection* conn = (connection*)pop_back(conn_list);
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
    free(hash_table);
    free(errbuf);

    return 0;
}

// this function handles the request packets.
// if the matched place in the hash table does not contain connections list,
// it creates new list with new connection and one transaction, and put it there.
// else it searchs in the list a connection with the tuples of the packet,
// if not found - creates new connection (include new transaction) and pushes to the list.
// else, inserts new transaction to the connection's transactions list.
static inline void req_packets_handle(uint hash_index, uint sourcePort, double epoch_time, five_tuple* key)
{
    list *conn_list = hash_table[hash_index];
    if (conn_list == NULL)
    {
        conn_list = malloc(SIZEOF_LIST);
        node* conn_node = malloc(SIZEOF_NODE);
        connection *conn = create_conn(epoch_time, key);
        conn_node->data = conn;
        conn_node->next = conn_node->prev = NULL;
        conn_list->head = conn_list->tail = conn_node;
        conn_list->size = 1;
        hash_table[hash_index] = conn_list;
        push_back(hash_used_places, conn_list);
    }
    else
    {
        node *conn_node = find_conn_in_list(conn_list, key);
        if (conn_node == NULL)
        {
            connection* conn = create_conn(epoch_time, key);
            push_front(conn_list, conn);
        }
        else
        {
            connection *conn = (connection*)conn_node->data;
            transaction *trans = create_trans(epoch_time);
            push_front(conn->trans_list, trans);
            conn->end_time = epoch_time;
        }
    }
}

// this function handles the inbound packets.
// it checks if exists connection with the packet's tuples, with help of the hash table, 
// if exit checks if the connection closed due to the timeout or number of transactions.
// if closed write the connection into csvfile, delete it from the list, and ignore the packet.
// else update the connection and his last transaction matching to the packet.
// if connection not exists, ignore the packet. 
static inline void in_packets_handle(uint hash_index, uint size, uint destPort, double epoch_time, five_tuple* key)
{
    list* conn_list = hash_table[hash_index];
    node* conn_node = find_conn_in_list(conn_list, key);
    if (conn_node != NULL)
    {
        connection *conn = (connection*)conn_node->data;
        if (epoch_time - conn->end_time > video_connection_timeout || 
            conn->trans_list->size >= max_number_of_transaction_per_video
           )
        {
            if (conn->size >= min_video_connection_size)
            {
                write_connection_into_csv(conn);
            }
            delete_from_list(conn_list, conn_node);
        }
        else
        {
            conn->size += size;
            node *trans_node =  conn->trans_list->head;
            transaction* trans = (transaction*)trans_node->data;
            double diff = epoch_time - conn->end_time;
            conn->end_time = trans->end_time = epoch_time;
            if (trans->RTT == -1)
            {
                trans->RTT = diff;
                trans->num_in_packets = 1;
                trans->min_packet_size_in = size;
                trans->max_packet_size_in = size;
                trans->min_diff_time_in = -1;
            }
            else
            {
                trans->num_in_packets++;
                if (trans->min_packet_size_in > size)
                {
                    trans->min_packet_size_in = size;
                }
                else if (trans->max_packet_size_in < size)
                {
                    trans->max_packet_size_in = size;
                }
                if (trans->min_diff_time_in == -1)
                {
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
        } 
    }
}

// this function handles the small outbound packets.
// it finds the connection who has the tuples of the packet, if exists,
// and updates his end_time and num_out_packets of his last transaction. 
static inline void small_out_packets_handle(uint hash_index, double epoch_time, five_tuple *key)
{
    list *conn_list = hash_table[hash_index];
    node *conn_node = find_conn_in_list(conn_list, key);
    if (conn_node != NULL)
    {
        connection *conn = (connection*)conn_node->data;
        node *trans_node = conn->trans_list->head;
        transaction* trans = (transaction*)trans_node->data;
        trans->num_out_packets++;
        conn->end_time = epoch_time;
    }
}

// this function gets the unique tuples of youtube packet, 
// creates a struct that contains them and returns his pointer.
static inline five_tuple *create_key_of_5_tuple(int client_ip, int server_ip, int clientPort)
{
    five_tuple *ft = malloc(SIZEOF_FIVET);
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
        transaction* trans = (transaction*)trans_node->data;

        average_duration_of_the_TDRs_per_video += trans->end_time - trans->start_time;
        average_time_between_two_consecutive_TDRs += trans->start_time - prev_time;
        prev_time = trans->end_time;

        // for a pretty format for the start time
        time_t packet_time = trans->start_time;
        struct tm *tmp = localtime(&packet_time);

        fprintf(csvfile, "%d, %s, %s, %d, %d, %d, %d, "
            "%d:%d:%d, %d, %d, %d, %d, %lf, %lf, null, %lf\n",
            sum_conn, server_addr,
            inet_ntoa(addr), IPPROTO_UDP,
            conn->key->udp_client_port, YOUTUBE_PORT,
            trans_id++, tmp->tm_hour, tmp->tm_min, tmp->tm_sec,
            trans->num_in_packets, trans->num_out_packets,
            trans->max_packet_size_in, trans->min_packet_size_in,
            trans->max_diff_time_in, trans->min_diff_time_in, trans->RTT);

        free(trans);
        node* prev = trans_node->prev;
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
    
    // print for visual fidback
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
