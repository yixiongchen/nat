
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
      if( (map->type == nat_mapping_icmp) && 
        (difftime(curtime, map->last_updated) >= nat->icmp_query_timeout)){
        /* free mapping in the middle of linked list*/
        if(prev){
          free_memory(map);
          prev->next = next;
          map = next;
        }
        /* free top of the linked list*/
        else{
          free_memory(map);
          map = next;
        }
      }

      /* handle tcp timeout
      else if(){
        if(prev){
          next = map->next;
          prev->next = next;  
        }

        else{
          next = map->next;
          nat->mappings = next; 
        }

        free_memory(map);
      }
      */

      else{
        prev = map;
        map = next;
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
  struct sr_nat_mapping *current = nat->mappings;
  struct sr_nat_mapping *copy; 
  printf("begin to find internal ip with external port %d\n",  aux_ext);
  while(current != NULL){
    if(current->type==type && current->aux_ext==aux_ext){
      printf("sucessfully find the internal ip with external port %d\n", aux_ext);
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      copy->type = current->type;
      copy->ip_int =current->ip_int;
      copy->ip_ext =current->ip_ext;
      copy->aux_int = current->aux_int;
      copy->aux_ext =current->aux_ext;

      copy->last_updated = current->last_updated;
      struct sr_nat_connection *connection;
      /*copy tcp connections*/
      if(current ->conns != NULL) {
        connection = (struct sr_nat_connection*) malloc(sizeof(struct sr_nat_connection));
        memcpy(connection, current->conns, sizeof(struct sr_nat_connection));
        struct sr_nat_connection *next_conn = current->conns->next;
        struct sr_nat_connection *result = connection;
        /*loop over each tcp connection*/
        while(next_conn != NULL){
	  if (ack && !syn & !fin){
	    switch (next_conn->state) {
	      case SYN_RCVD:
		next_conn->state = ESTAB;
		break;
	      /* No need to consider TIME_WAIT and CLOSED.
	      case CLOSING:
		next_conn->state = TIME_WAIT;
		break;
	      case LAST_ACK:
		next_conn->state = CLOSED;
		break;*/
	      default:
		break;
	    }
	  }
	  else if (!ack && !syn && fin && next_conn->state == ESTAB) {
	    next_conn->state = CLOSE_WAIT;
	  }
	  else if (ack && !syn && fin && next_conn->state == FIN_WAIT_1) {
	    next_conn->state = FIN_WAIT_2;
	  }
          struct sr_nat_connection *nested = (struct sr_nat_connection*) malloc(sizeof(struct sr_nat_connection));
          memcpy(nested, next_conn, sizeof(struct sr_nat_connection));
          result-> next = nested;
          result = result-> next;
          next_conn = next_conn->next;
        }  
      }
      copy->conns = connection;
      copy->next = NULL;
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
  printf("begin %d\n",aux_int);
  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *current = nat->mappings;
  printf("one. \n");
  struct sr_nat_mapping *copy = NULL;
  printf("two. \n");
  while(current != NULL){
     printf("nat_mapping is not null. \n");
    if(current->type==type && current->aux_int==aux_int && current->ip_int==ip_int){
      printf("already exist in. \n");
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      bzero(copy, sizeof(struct sr_nat_mapping));
      copy->type = current->type;
      copy->ip_int=current->ip_int;
      copy->ip_ext=current->ip_ext;
      copy->aux_int=current->aux_int;
      copy->aux_ext=current->aux_ext;
      copy->last_updated = current->last_updated;
      struct sr_nat_connection *connection = NULL;
      /*copy tcp connections*/
      if(current->conns != NULL) {
        connection = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
        memcpy(connection, current->conns, sizeof(struct sr_nat_connection));
        struct sr_nat_connection *next_conn = current->conns->next;
        struct sr_nat_connection *result = connection;
        /*loop over each tcp connection*/
        while(next_conn != NULL){
          struct sr_nat_connection *nested = (struct sr_nat_connection*) malloc(sizeof(struct sr_nat_connection));
	  /* Check if it's the same connection*/
	  if (next_conn->outhost_ip == dst_ip && next_conn->outhost_port == dst_port){
	    if (ack && !syn && !fin) {
	      switch (next_conn->state) {
		case SYN_SENT:
		  next_conn->state = ESTAB;
		  break;
		case FIN_WAIT_1:
		  next_conn->state = CLOSING;
		  break;
		/* No need for time_wait.
		case FIN_WAIT_2:
		  next_conn->state = TIME_WAIT;
		  break;
		*/
		default:
		  break;
	      }
	    }
	    else if (!ack && !syn && fin) {
	      switch (next_conn->state) {
		case SYN_RCVD:
		case ESTAB:
		  next_conn->state = FIN_WAIT_1;
		  break;
		case CLOSE_WAIT:
		  next_conn->state = LAST_ACK;
		  break;
		default:
		  break;
	      }
	    }
	    else if (ack && !syn && fin && next_conn->state == ESTAB) {
	      next_conn->state = CLOSE_WAIT;
	    }
	  }
          memcpy(nested, next_conn, sizeof(struct sr_nat_connection));
          result-> next = nested;
          result = result-> next;
          next_conn = next_conn->next;
        } 
      }
      copy->conns = connection;
      copy->next = NULL;
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
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type, uint32_t outhost_ip, uint16_t outhost_port, int sendsyn) {
  
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
    if (sendsyn){
      new_conn->state = SYN_SENT;
    } 
    else{
      new_conn->state = SYN_RCVD;
    }
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




