
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sr_if.h"
#include "sr_router.h"
#include "sr_utils.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */
  
  
  assert(nat);
  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);
  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
  nat->mappings = NULL;
  nat->max_port = 1024;
    
  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */
  pthread_mutex_lock(&(nat->lock)); 
  /* free nat memory here */
  struct sr_nat_mapping* current = nat->mappings;
  while(current != NULL){
    struct sr_nat_mapping* next = current->next;
    /* free sr_nat_mapping*/
    free_memory(current);
    current = next;
  }
  free(nat);
  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));

}


void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));
    time_t curtime = time(NULL);
    /* handle periodic tasks here */
    struct sr_nat_mapping* map = nat->mappings; 
    struct sr_nat_mapping* prev = NULL;
    while (map){
      /* handle imcp timeout*/
      struct sr_nat_mapping* next = map->next;
      if (map->type == nat_mapping_icmp){
        if (difftime(curtime, map->last_updated) >= nat->icmp_query_timeout){
          /* free mapping in the middle of linked list*/
          if(prev){
            free(map);
            prev->next = next;
            map = next;
          }
          /* free top of the linked list*/
          else{
            free(map);
            map = next;
            nat->mappings = map;
          }
        }
        else{
          prev = map;
          map = next;
        }
      }

      /* handle tcp timeout */
      else{
        struct sr_nat_connection *connection = map->conns;
        struct sr_nat_connection *prev_conn = NULL;
        while (connection){
          struct sr_nat_connection *next_conn = connection->next;
          switch (connection->state){
            case SYN_SENT:
            case SYN_RCVD:
            case CLOSING:
            case LAST_ACK:
              if (difftime(curtime, connection->last_updated) >= nat->tcp_trans_timeout){
                if(prev_conn){
                  free(connection);
                  prev_conn->next = next_conn;
                  connection = next_conn;
                }
                /* free top of the linked list*/
                else{
                  free(connection);
                  connection = next_conn;
                  map->conns = connection;
                }
              }
              else{
                prev_conn = connection;
                connection = next_conn;
              }
              break;
            case ESTAB:
            case FIN_WAIT_1:
            case FIN_WAIT_2:
            case CLOSE_WAIT:
              if (difftime(curtime, connection->last_updated) >= nat->tcp_est_timeout){
                if(prev_conn){
                  free(connection);
                  prev_conn->next = next_conn;
                  connection = next_conn;
                }
                /* free top of the linked list*/
                else{
                  free(connection);
                  connection = next_conn;
                  map->conns = connection;
                }
              }
              else{
                prev_conn = connection;
                connection = next_conn;
              }
              break;
          }
        }
        if (!map->conns){
          if(prev){
            free(map);
            prev->next = next;
            map = next;
          }
          /* free top of the linked list*/
          else{
            free(map);
            map = next;
            nat->mappings = map;
          }
        }
        else{
          prev = map;
          map = next;
        }
      }
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}
  


/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type, uint32_t src_ip, uint16_t src_port, int ack, int syn, int fin) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  time_t now = time(NULL);
  struct sr_nat_mapping *current = nat->mappings;
  struct sr_nat_mapping *copy = NULL; 
  printf("begin to find internal ip with external port %d\n",  aux_ext);
  while(current != NULL){
    if(current->type==type && current->aux_ext==aux_ext){
      printf("sucessfully find the internal ip with external port %d\n", aux_ext);
      if (!ack && syn && !fin){
        struct sr_nat_connection* new_conn = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
        new_conn->next = current->conns;
        new_conn->outhost_port = src_port;
        new_conn->outhost_ip = src_ip;
        new_conn->state = SYN_RCVD;
        new_conn->last_updated = now;
        current->conns = new_conn;
      }
      else{
        /*loop over each tcp connection*/
        struct sr_nat_connection *connection = current->conns;
        while (connection) {
          if (connection->outhost_ip == src_ip && connection->outhost_port == src_port){
            if (ack && !syn & !fin){
              switch (connection->state) {
                case SYN_RCVD:
                  connection->state = ESTAB;
                  connection->last_updated = now;
                  break;
                /* No need to consider TIME_WAIT and CLOSED.
                case CLOSING:
                  connection->state = TIME_WAIT;
                  break;
                case LAST_ACK:
                  connection->state = CLOSED;
                  break;*/
                default:
                  break;
              }
            }
            else if (!ack && !syn && fin && connection->state == ESTAB) {
              connection->state = CLOSE_WAIT;
            }
            else if (ack && !syn && fin && connection->state == FIN_WAIT_1) {
              connection->state = FIN_WAIT_2;
            }
            break;
          }
          connection = connection->next;  
        }
      }
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, current, sizeof(struct sr_nat_mapping));
      break; 
    }
    current = current->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, uint32_t dst_ip, uint16_t dst_port, int ack, int syn, int fin) {
  pthread_mutex_lock(&(nat->lock));
  printf("Begin to look for external port using internal.\n");
  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *current = nat->mappings;
  struct sr_nat_mapping *copy = NULL;
  time_t now = time(NULL);
  while(current != NULL){
    if(current->type==type && current->aux_int==aux_int && current->ip_int==ip_int){
      printf("Found mapping with aux_ext = %d\n", current->aux_ext);
      if (!ack && syn && !fin){
        struct sr_nat_connection* new_conn = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
        new_conn->next = current->conns;
        new_conn->outhost_port = dst_port;
        new_conn->outhost_ip = dst_ip;
        new_conn->state = SYN_SENT;
        new_conn->last_updated = now;
        current->conns = new_conn;
      }
      else{
        struct sr_nat_connection *connection = current->conns;
        /*loop over each tcp connection*/
        while(connection){
          /* Check if it's the same connection*/
          if (connection->outhost_ip == dst_ip && connection->outhost_port == dst_port){
            if (ack && !syn && !fin) {
              switch (connection->state) {
                case SYN_SENT:
                  connection->state = ESTAB;
                  connection->last_updated = now;
                  break;
                case FIN_WAIT_1:
                  connection->state = CLOSING;
                  connection->last_updated = now;
                  break;
                /* No need for time_wait.
                case FIN_WAIT_2:
                  connection->state = TIME_WAIT;
                  break;
                */
                default:
                  break;
              }
            }
            else if (!ack && !syn && fin) {
              switch (connection->state) {
                case SYN_RCVD:
                case ESTAB:
                  connection->state = FIN_WAIT_1;
                  connection->last_updated = now;
                  break;
                case CLOSE_WAIT:
                  connection->state = LAST_ACK;
                  connection->last_updated = now;
                  break;
                default:
                  break;
              }
            }
            else if (ack && !syn && fin && connection->state == ESTAB) {
              connection->state = CLOSE_WAIT;
            }
            break;
          }
          connection = connection->next;
        } 
      }
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, current, sizeof(struct sr_nat_mapping));
      break; 
    }
    current = current->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, uint32_t outhost_ip, uint16_t outhost_port) {
  
  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *map= NULL;
  /*loop to the end of list and get the largest external port number */
  map = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
  /* create a new external port number */
  /* update new mapping data */
  map->type = type;
  map->ip_int = ip_int;
  map->ip_ext = nat->ip_ext;
  map->aux_int = aux_int;
  map->aux_ext = nat->max_port + 1;

  time_t now = time(NULL);
  map->last_updated = now;
  /* handle icmp */
  if(type == nat_mapping_icmp){
    map->conns = NULL; 
  }
  /* handle tcp */
  else if(type==nat_mapping_tcp){
    struct sr_nat_connection* new_conn = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
    new_conn->next = NULL;
    new_conn->outhost_port = outhost_port;
    new_conn->outhost_ip = outhost_ip;
    new_conn->state = SYN_SENT;
    new_conn->last_updated = now;
    map->conns = new_conn;
  }
  nat->max_port = map->aux_ext;
  map->next = nat->mappings;
  nat->mappings = map;

  pthread_mutex_unlock(&(nat->lock));
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
  memcpy(copy, map, sizeof(struct sr_nat_mapping));
  return copy;
}



/* free sr_nat_mapping struct
 */
int free_memory(struct sr_nat_mapping* map){
  if(map != NULL){
    /* free all sr_nap_connections */
    struct sr_nat_connection* connection = map->conns;
    struct sr_nat_connection* next;
    while(connection != NULL){
      next = connection->next;
      free(connection);
      connection = next;
    }
    free(map);
    return 1;
  }
  return 0;
}




