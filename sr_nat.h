
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef int Boolean;
#define true 1
#define false 0



struct sr_nat_connection {
  /* add TCP connection state data members here */
  time_t initialized; /*time initialize a tcp session*/
  Boolean status; /* it is closed or open*/
  int sequence; /*sequences number of TCP packets*/
  uint32_t ack; /* acknowledgment */
  int tcp_fin;
  int tcp_syn;
  int tcp_ack; 
  struct sr_nat_connection *next;
};


struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};


struct sr_nat {
  /* add any fields here */
  int icmp_query_timeout;  /* ICMP query timeout interval in seconds */
  int tcp_est_timeout;  /* TCP Established Idle Timeout in seconds */
  int tcp_trans_timeout;  /* TCP Transitory Idle Timeout in seconds */
  uint32_t ip_ext;
  uint16_t max_port;
  struct sr_nat_mapping *mappings;
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */


/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type, uint32_t src_ip, uint16_t src_port, int ack, int syn, int fin);

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, uint32_t dst_ip, uint16_t dst_port, int ack, int syn, int fin);

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
/* sendsyn = 1 if tcp packet from internal to external, 0 for all other cases */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, uint32_t outhost_ip, uint16_t outhost_port, int sendsyn);

/* Free the returned Mapping 
*/
 int free_memory(struct sr_nat_mapping* map);

#endif
