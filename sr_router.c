

/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  printf("Received packet:\n");
  print_hdrs(packet, len);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  /* add nat external ip address */
  struct sr_if *nat_ext_iface; /* nat's outgoing interface */
  nat_ext_iface = sr_get_interface(sr, EXT_INTERFACE);
  assert(nat_ext_iface);
  sr->nat->ip_ext = nat_ext_iface->ip;

  sr_ethernet_hdr_t *ethernet_hdr;

  if ( len < sizeof(struct sr_ethernet_hdr) ) {
        fprintf(stderr , "** Error: packet is way too short \n");
        return;
  }

  ethernet_hdr = (struct sr_ethernet_hdr *)packet;
  assert(ethernet_hdr);

  /* if the packet is an arp packet */
  if (ethernet_hdr->ether_type == htons(ethertype_arp)) {
    sr_handle_arp_pkt(sr, packet, len, interface);    
  }

  /* if the packet is an ip packet */
  if (ethernet_hdr->ether_type == htons(ethertype_ip)) {
    sr_handle_ip_pkt(sr, packet, len, interface);
  }

  return;
}/* end sr_handlepacket */

/* helper function for sr_handlepacket()
 * if the packet is an arp packet */
int sr_handle_arp_pkt(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)) {
        fprintf(stderr , "** Error: packet is way too short \n");
        return -1;
  }

  sr_arp_hdr_t *arp_hdr;
  arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(arp_hdr);
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);

  /* check if the arp is for me */
  if (arp_hdr->ar_tip != iface->ip) {
    return 0;
  }

  /* if the arp is an arp request and target ip is me */
  if (arp_hdr->ar_op == htons(arp_op_request)) {  
    sr_handle_arp_request(sr, packet, len, interface);
  }

  /* if the arp is an arp reply to me */
  if (arp_hdr->ar_op == htons(arp_op_reply)) {
    sr_handle_arp_reply(sr, packet, len, interface);
  }  

  return 0;
} /* end sr_handle_arp_pkt */

/* handle arp request to me */
void sr_handle_arp_request(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_arp_hdr_t *arp_hdr;
  struct sr_if* iface;
  uint8_t *sr_pkt;

  iface = sr_get_interface(sr, interface);
  assert(iface);
  /* make a copy of the packet */
  sr_pkt = (uint8_t *)malloc(len);
  memcpy(sr_pkt, packet, len);  

  ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
  arp_hdr = (sr_arp_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
  assert(ethernet_hdr);
  assert(arp_hdr);

  /* update arp header */
  arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = arp_hdr->ar_sip;    
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface->ip;

  /* update ethernet header */
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  printf("Send packet:\n");
  print_hdrs(sr_pkt, len);
  sr_send_packet(sr, sr_pkt, len, interface);
  free(sr_pkt);

  return;
} /* end sr_handle_arp_request */

/* handle arp reply to me */
void sr_handle_arp_reply(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{  
  sr_arp_hdr_t *arp_hdr;  
  arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(arp_hdr);  

  /* cache the arp reply */
  struct sr_arpreq *req;
  req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

  /* forward packets waiting on this arp reply */
  if (req) {
    sr_ethernet_hdr_t *ethernet_hdr;
    sr_ip_hdr_t *ip_hdr;

    struct sr_if* o_iface; /* outgoing interface */
    struct sr_packet *pkt;   
    for (pkt = req->packets; pkt; pkt = pkt->next) {
      o_iface = sr_get_interface(sr, pkt->iface);
      assert(o_iface);
      /* update ethernet header */
      ethernet_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
      memcpy(ethernet_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN);
      
      /* update ip header */
      ip_hdr = (struct sr_ip_hdr *)(pkt->buf + sizeof(struct sr_ethernet_hdr));
      ip_hdr->ip_ttl--;
      bzero(&(ip_hdr->ip_sum), 2);
      
      /* Send packet with NAT.*/
      if (sr->nat_on == 1) {

      	/* If it's an ICMP packet*/
      	if (ip_hdr->ip_p == ip_protocol_icmp) {
      	  sr_icmp_hdr_t *icmp_hdr;
      	  icmp_hdr = (sr_icmp_hdr_t *)(pkt->buf + sizeof(struct sr_ethernet_hdr)
      	    + sizeof(struct sr_ip_hdr));

      	  /* If it's an ICMP echo request*/
      	  if (icmp_hdr->icmp_type == 8) {
            /* printf("pass icmp = 8.\n"); */
            uint16_t *aux_src_int;
            uint32_t *ip_src_int;
            ip_src_int = &(ip_hdr->ip_src);
            aux_src_int = (uint16_t *)(pkt->buf + sizeof(struct sr_ethernet_hdr) 
              + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr));

            /* printf("next is mapping for icmp = 8.\n"); */

            struct sr_nat_mapping *nat_mapping;

            /* printf("src_ip %u\n", *ip_src_int ); */
            /* printf("port_int %d\n",*aux_src_int); */
              nat_mapping = sr_nat_lookup_internal(sr->nat, *ip_src_int, 
                *aux_src_int, nat_mapping_icmp, 0, 0, 0, 0, 0);

            /* printf("pass look up.\n"); */
            /* Create new mapping if existing mapping not found.*/
            if (!nat_mapping) {

              nat_mapping = sr_nat_insert_mapping(sr->nat, *ip_src_int, 
                *aux_src_int, nat_mapping_icmp, 0, 0, 0);
        	  }

      	    ip_hdr->ip_src = nat_mapping->ip_ext;
      	    
      	    /* update icmp query id */
      	    sr_icmp_t8_hdr_t *icmp_hdr_new;
      	    icmp_hdr_new = (sr_icmp_t8_hdr_t *)(pkt->buf + 
      	      sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_id = nat_mapping->aux_ext;
      	    bzero(&(icmp_hdr_new->icmp_sum), 2);
      	    uint16_t icmp_cksum = cksum(icmp_hdr_new, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_sum = icmp_cksum;
            free(nat_mapping);
        	}
      	  /* If it's an ICMP echo reply*/
      	  else if (icmp_hdr->icmp_type == 0 && ip_hdr->ip_dst == sr->nat->ip_ext){
	          uint16_t *aux_ext;
      	    aux_ext = (uint16_t *)(pkt->buf + sizeof(struct sr_ethernet_hdr) 
      	      + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr));
      	    struct sr_nat_mapping *nat_mapping;
      	    nat_mapping = sr_nat_lookup_external(sr->nat, *aux_ext, nat_mapping_icmp, 0, 0, 0, 0, 0);

      	    /* If no mapping, drop the packet.*/
      	    if (!nat_mapping) {
      	      fprintf(stderr , "** Error: No mapping found when forwarding icmp reply.");
	            return;
      	    }
    	    
      	    ip_hdr->ip_dst = nat_mapping->ip_int;
      	    
      	    /* update icmp query id */
      	    sr_icmp_t8_hdr_t *icmp_hdr_new;
      	    icmp_hdr_new = (sr_icmp_t8_hdr_t *)(pkt->buf + 
      	      sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_id = nat_mapping->aux_ext;
      	    bzero(&(icmp_hdr_new->icmp_sum), 2);
      	    uint16_t icmp_cksum = cksum(icmp_hdr_new, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_sum = icmp_cksum;
            free(nat_mapping);
          }
	      }
      
        /* If it's an TCP packet*/
        if (ip_hdr->ip_p == ip_protocol_tcp) {

          sr_tcp_hdr_t *tcp_hdr;
          tcp_hdr = (sr_tcp_hdr_t *)(pkt->buf + sizeof(struct sr_ethernet_hdr) + 
            sizeof(struct sr_ip_hdr));

          uint8_t flag = tcp_hdr->flag;
          int ack = flag & (1<<4);
          int syn = flag & (1<<1);          
          int fin = flag & 1;          

          /* if the tcp is from internal to external */
          if (strcmp(pkt->iface, EXT_INTERFACE) == 0) {
            /* get source ip and port number */
            uint32_t ip_src_int = ip_hdr->ip_src;
            uint16_t aux_src_int = tcp_hdr->port_src;

            /* find nat mapping */
            struct sr_nat_mapping *nat_mapping;
            nat_mapping = sr_nat_lookup_internal(sr->nat, ip_src_int, 
              aux_src_int, nat_mapping_icmp, ip_hdr->ip_dst, tcp_hdr->port_dst, ack, syn, fin);

            /* Create new mapping if existing mapping not found.*/
            if (!nat_mapping) {
              nat_mapping = sr_nat_insert_mapping(sr->nat, ip_src_int, 
                   aux_src_int, nat_mapping_tcp, ip_hdr->ip_dst, tcp_hdr->port_dst, 1);
            }

            /* translate ip source address */
            ip_hdr->ip_src = nat_mapping->ip_ext;            
            /* translate tcp source port number */
            tcp_hdr->port_src = nat_mapping->aux_ext;
            /* recalculate tcp chechsum */
            bzero(&(tcp_hdr->tcp_sum), 2);
            uint16_t tcp_cksum = cksum(tcp_hdr, len - 
              sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
            tcp_hdr->tcp_sum = tcp_cksum;
            free(nat_mapping);

          }

          /* if the tcp is from external to internal */
          if (strcmp(pkt->iface, INT_INTERFACE) == 0) {
            /* get destination port number */
            uint16_t aux_ext = tcp_hdr->port_dst;

            /* find nat mapping */            
            struct sr_nat_mapping *nat_mapping;
            nat_mapping = sr_nat_lookup_external(sr->nat, aux_ext, nat_mapping_tcp, 
              ip_hdr->ip_src, tcp_hdr->port_src, ack, syn, fin);
            
            /* If no mapping, drop the packet.*/
            if (!nat_mapping) {
              fprintf(stderr , "** Error: No mapping found when forwarding tcp packet.");
              return;
            }
            
            /* translate ip destination address */
            ip_hdr->ip_dst = nat_mapping->ip_int;
            /* translate tcp destination port number */
            tcp_hdr->port_src = nat_mapping->aux_int;
            /* recalculate tcp chechsum */
            bzero(&(tcp_hdr->tcp_sum), 2);
            uint16_t tcp_cksum = cksum(tcp_hdr, len - 
              sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
            tcp_hdr->tcp_sum = tcp_cksum;
            free(nat_mapping);
          }
        }
      }
      
      uint16_t ip_cksum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));
      ip_hdr->ip_sum = ip_cksum;

      printf("Send packet in ARP queue where:\n");
      print_hdrs(pkt->buf, pkt->len);
      sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
    }

    sr_arpreq_destroy(&(sr->cache), req);
  }
  
  return;
} /* end sr_handle_arp_reply */

/* if the packet is an ip packet */
int sr_handle_ip_pkt(struct sr_instance* sr,
        uint8_t * packet, 
        unsigned int len,
        char* interface) 
{
  if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)) {
        fprintf(stderr , "** Error: packet is way to short \n");
        return -1;
  }

  
  sr_ip_hdr_t *ip_hdr;
  sr_icmp_t8_hdr_t *icmp_t8_hdr;
  sr_tcp_hdr_t *tcp_hdr;
  struct sr_nat_mapping *nat_mapping = NULL;

  ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ip_hdr); 

  /* verify ip header checksum */  
  if (cksum(ip_hdr, sizeof(struct sr_ip_hdr)) != 0xffff) {
    fprintf(stderr , "** Error: ip_packet received with error\n");
    return -1;
  }

  /* Look for nat mapping for corresponding dst_ip and dst_aux. */
  /* if the ip packet is an icmp packet */
  if (sr->nat_on){
    if (ip_hdr->ip_p == ip_protocol_icmp) {
      icmp_t8_hdr = (sr_icmp_t8_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + 
      sizeof(struct sr_ip_hdr));
      /* If the packet comes from outside. */
      if (ip_hdr->ip_dst == sr->nat->ip_ext){
        nat_mapping = sr_nat_lookup_external(sr->nat, icmp_t8_hdr->icmp_id, nat_mapping_icmp, 0, 0, 0, 0, 0);
      }
    }

    /* if the ip packet is a tcp packet */
    if (ip_hdr->ip_p == ip_protocol_tcp) {
      tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + 
        sizeof(struct sr_ip_hdr));

      uint8_t flag = tcp_hdr->flag;
      int ack = flag & (1<<4);
      int syn = flag & (1<<1);          
      int fin = flag & 1;          

      /* If the packet comes from outside.*/
      if (ip_hdr->ip_dst == sr->nat->ip_ext){
        nat_mapping = sr_nat_lookup_external(sr->nat, tcp_hdr->port_dst, nat_mapping_tcp, 
          ip_hdr->ip_src, tcp_hdr->port_src, ack, syn, fin);
        if (!nat_mapping){
          sleep(6);
          nat_mapping = sr_nat_lookup_external(sr->nat, tcp_hdr->port_dst, nat_mapping_tcp, 
            ip_hdr->ip_src, tcp_hdr->port_src, ack, syn, fin);
        }
      }
    }
  }
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);

  /* if the ip packet is for me */
  struct sr_if *my_iface;  

  for (my_iface = sr->if_list; my_iface != NULL; my_iface = my_iface->next){
    if ((ip_hdr->ip_dst == my_iface->ip) && (!nat_mapping)) {
      sr_handle_pkt_for_me(sr, packet, len, interface);
      return 0;
    }
  }

  /*
  if (ip_hdr->ip_dst == iface->ip) {
    sr_handle_icmp_pkt(sr, packet, len, interface);
  }
  */

  /* if it is not for me and its ttl greater than 1 */
  if (ip_hdr->ip_ttl > 1) {
    sr_forward_ip_pkt(sr, packet, len, interface);
  }
  /* if it is not for me and ttl equal or less than 1,
   * drop the packet and send an icmp message to source ip */
  else {
    sr_icmp_dest_unreachable(sr, packet, len, interface, 11, 0);
    fprintf(stderr , "** Error: packet received with time exceeded\n");
    return -1;
  }

  return 0;
} /* end sr_handle_ip_pkt */


/* handle icmp echo request to me */
int sr_handle_pkt_for_me(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t *ip_hdr;
  sr_icmp_hdr_t *icmp_hdr;
  struct sr_if* iface = sr_get_interface(sr, interface);  
  assert(iface);

  ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
  /* if it is an icmp echo request for me */
  if (ip_hdr->ip_p == ip_protocol_icmp) {
    /* sanity check */
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + 
              sizeof(struct sr_icmp_hdr)) {
        fprintf(stderr , "** Error: packet is way too short \n");
        return -1;
    }

    icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) +
        sizeof(struct sr_ip_hdr));      
  
    if (cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr)) != 0xffff) {
      fprintf(stderr , "** Error: icmp_packet received with error\n");
      return -1;

    }

    if (icmp_hdr->icmp_type == 8) {  /* icmp echo request */
      /* make a copy of the packet */
      uint8_t *sr_pkt = (uint8_t *)malloc(len);
      memcpy(sr_pkt, packet, len);

      /* update icmp header */
      uint16_t icmp_cksum;
      icmp_hdr = (sr_icmp_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr) +
              sizeof(struct sr_ip_hdr));
      icmp_hdr->icmp_type = 0;  /* set icmp type to echo reply */
      /* recalculate checksum */
      bzero(&(icmp_hdr->icmp_sum), 2);
      icmp_cksum = cksum(icmp_hdr, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));
      icmp_hdr->icmp_sum = icmp_cksum;

      /*update ip header */
      ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
      
      uint32_t reply_src;
      reply_src = ip_hdr->ip_dst;
      ip_hdr->ip_dst = ip_hdr->ip_src;
      ip_hdr->ip_src = reply_src;
      /* LPM */
      struct sr_rt *rtable;
      rtable = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
      if (rtable->gw.s_addr) {
        struct sr_if *o_iface = sr_get_interface(sr, rtable->interface);
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_ttl = 0xff;
        bzero(&(ip_hdr->ip_sum), 2);
        uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
        ip_hdr->ip_sum = ip_cksum;

        /* check arp cache for next hop mac */
        struct sr_arpentry *arp_entry; 
        arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

        /*arp cache hit */
        if (arp_entry) {
          /* update ethernet header */
          ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
          memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
          memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN);         

          /* send icmp echo reply packet */
          printf("Send packet:\n");
          print_hdrs(sr_pkt, len);
          sr_send_packet(sr, sr_pkt, len, rtable->interface);
        }

        /* arp miss */
        else {
          uint8_t *arp_packet = construct_arp_buff(o_iface->addr,  o_iface->ip, rtable->gw.s_addr);
          sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + 
            sizeof(struct sr_arp_hdr), rtable->interface);
          sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, sr_pkt, len, rtable->interface);
        }      
      }

      free(sr_pkt);
    }
  } 
  
  else if ((len > (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr))) &&
    ((ip_hdr->ip_p == 0x0006) || (ip_hdr->ip_p == 0x0011))) {  
    /* icmp port unreachable */
    sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 3);
  }  

  return 0;
} /* end sr_handle_pkt_for_me */


/* send icmp destination unreachable message */
void sr_icmp_dest_unreachable(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface,
        uint8_t icmp_type,     
        uint8_t icmp_code)
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t *ip_hdr;
  sr_icmp_t3_hdr_t *icmp_t3_hdr;
  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);
  unsigned int pkt_len;

  /* construct the icmp packet */
  pkt_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
  uint8_t *sr_pkt = (uint8_t *)malloc(pkt_len);
  memcpy(sr_pkt, packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  /* update icmp header */
  icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr) + 
    sizeof(struct sr_ip_hdr));
  icmp_t3_hdr->icmp_type = icmp_type;
  icmp_t3_hdr->icmp_code = icmp_code;
  bzero(&(icmp_t3_hdr->icmp_sum), 2);
  bzero(&(icmp_t3_hdr->unused), 2);
  bzero(&(icmp_t3_hdr->next_mtu), 2);
  memcpy(icmp_t3_hdr->data, packet + sizeof(struct sr_ethernet_hdr), ICMP_DATA_SIZE);
  uint16_t icmp_cksum = cksum(icmp_t3_hdr, sizeof(struct sr_icmp_t3_hdr));
  icmp_t3_hdr->icmp_sum = icmp_cksum;

  /* update ip header */ 
  ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));

  /* Drop packet if ip_src is me */
  struct sr_if *my_iface;
  for (my_iface = sr->if_list; my_iface != NULL; my_iface = my_iface->next){
    if (my_iface->ip == ip_hdr->ip_src){
      return;
    }
  }
  
  if (icmp_code == 3){
    uint32_t reply_src;
    reply_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = reply_src;
  }
  else{
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = iface->ip;
  }
  ip_hdr->ip_ttl = 0xff;
  ip_hdr->ip_p = ip_protocol_icmp;
  bzero(&(ip_hdr->ip_sum), 2);
  uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
  ip_hdr->ip_sum = ip_cksum;

  /* update ethernet header */
  ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* send icmp packet */
  printf("Send packet:\n");
  print_hdrs(sr_pkt, pkt_len);
  sr_send_packet(sr, sr_pkt, pkt_len, interface);
  free(sr_pkt);
  fprintf(stderr , "** Error: destination unreachable with error code %d.\n", icmp_code);

  return;
} /* sr_icmp_dest_unreachable */

/* forward ip packet */
void sr_forward_ip_pkt(struct sr_instance* sr,
        uint8_t  *packet, 
        unsigned int len,
        char* interface) 
{
  sr_ethernet_hdr_t *ethernet_hdr;
  sr_ip_hdr_t * ip_hdr;  

  ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ip_hdr);
    
  /* Routing with NAT. */
  if (sr->nat_on == 1) {
    
    /* Get the original source and destination ips from packet.*/
    uint32_t original_ip_src, original_ip_dst;
    original_ip_src = ip_hdr->ip_src;
    original_ip_dst = ip_hdr->ip_dst;
      
    /* If it's an ICMP packet*/
    if (ip_hdr->ip_p == ip_protocol_icmp) {
      
      /* Get the original icmp query id from packet.*/
      sr_icmp_hdr_t *original_icmp_hdr;
      original_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + 
        sizeof(struct sr_ip_hdr));
      
      uint16_t *original_icmp_id;
      original_icmp_id = (uint16_t *)(packet + sizeof(struct sr_ethernet_hdr) + 
        sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr));
      
      /* If it's an ICMP echo request*/
      if (original_icmp_hdr->icmp_type == 8) {        
	
      	/* lookup the longest prefix match */
      	struct sr_rt *rtable = sr_longest_prefix_match(sr, original_ip_dst);

      	/* if no match, icmp net unreachable */
      	if (! rtable->gw.s_addr) {
      	  sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 0);
      	  return;
      	}
	
      	/* match */
      	else {
      	  
      	  /* Look for nat mapping for corresponding src_ip and src_aux. */
      	  struct sr_nat_mapping *nat_mapping;
      	  nat_mapping = sr_nat_lookup_internal(sr->nat, original_ip_src, 
            *original_icmp_id, nat_mapping_icmp, 0, 0, 0, 0, 0);
	  
      	  /* Create new mapping if existing mapping not found.*/
      	  if (!nat_mapping) {
      	    nat_mapping = sr_nat_insert_mapping(sr->nat, original_ip_src, 
      					*original_icmp_id, nat_mapping_icmp, 0, 0, 0);
      	  }
      	  
      	  struct sr_if* o_iface = sr_get_interface(sr, EXT_INTERFACE);
      	  assert(o_iface);

      	  /* make a copy of the packet */
      	  uint8_t *sr_pkt = (uint8_t *)malloc(len);
      	  memcpy(sr_pkt, packet, len);

      	  /* check arp cache for next hop mac */
      	  struct sr_arpentry *arp_entry; 
      	  arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

      	  /*arp cache hit */
      	  if (arp_entry) {
      	    /* update ethernet header */
      	    ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
      	    memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
      	    memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN); 
      	  
      	    /* update ip header */
      	    ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
      	    ip_hdr->ip_ttl--;
      	    ip_hdr->ip_src = nat_mapping->ip_ext;
      	    bzero(&(ip_hdr->ip_sum), 2);  
      	    uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
      	    ip_hdr->ip_sum = ip_cksum;
      	    
      	    /* update icmp query id */
      	    sr_icmp_t8_hdr_t *icmp_hdr_new;
      	    icmp_hdr_new = (sr_icmp_t8_hdr_t *)(sr_pkt + 
      	      sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_id = nat_mapping->aux_ext;
      	    bzero(&(icmp_hdr_new->icmp_sum), 2);
      	    uint16_t icmp_cksum = cksum(icmp_hdr_new, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_sum = icmp_cksum;

      	    /* send frame to next hop */
      	    printf("Send packet with NAT:\n");
      	    print_hdrs(sr_pkt, len);
      	    sr_send_packet(sr, sr_pkt, len, rtable->interface);
      	    free(arp_entry);
      	  }    
      	  /* arp miss */
      	  else {
      	    sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, 
      				 rtable->interface);
      	  }
      	  free(sr_pkt);
      	  free(rtable); 
          free(nat_mapping);
      	}
      }

      /* If it's an ICMP echo reply*/
      else if (original_icmp_hdr->icmp_type == 0) {
      	/* Look for nat mapping for corresponding dst_ip and dst_aux. */
      	struct sr_nat_mapping *nat_mapping;
      	nat_mapping = sr_nat_lookup_external(sr->nat, *original_icmp_id, nat_mapping_icmp, 0, 0, 0, 0, 0);
      	
      	if (!nat_mapping) {
      	  fprintf(stderr , "** Error: No mapping found when forwarding icmp reply.");
      	  return;
      	}
	
	      /* lookup the longest prefix match */
      	struct sr_rt *rtable = sr_longest_prefix_match(sr, nat_mapping->ip_int);

      	/* if no match, icmp net unreachable */
      	if (! rtable->gw.s_addr) {
      	  sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 0);
      	  return;
      	}
      	/* match */
      	else {
	        struct sr_if* o_iface = sr_get_interface(sr, INT_INTERFACE);
      	  assert(o_iface);

      	  /* make a copy of the packet */
      	  uint8_t *sr_pkt = (uint8_t *)malloc(len);
      	  memcpy(sr_pkt, packet, len);

      	  /* check arp cache for next hop mac */
      	  struct sr_arpentry *arp_entry; 
      	  arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

      	  /*arp cache hit */
      	  if (arp_entry) {
      	    /* update ethernet header */
      	    ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
      	    memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
      	    memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN); 
      	  
      	    /* update ip header */
      	    ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
      	    ip_hdr->ip_ttl--;
      	    ip_hdr->ip_dst = nat_mapping->ip_int;
      	    bzero(&(ip_hdr->ip_sum), 2);  
      	    uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
      	    ip_hdr->ip_sum = ip_cksum;
      	    
      	    /* update icmp query id */
      	    sr_icmp_t8_hdr_t *icmp_hdr_new;
      	    icmp_hdr_new = (sr_icmp_t8_hdr_t *)(sr_pkt + 
      	      sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_id = nat_mapping->aux_int;
      	    bzero(&(icmp_hdr_new->icmp_sum), 2);
      	    uint16_t icmp_cksum = cksum(icmp_hdr_new, len - sizeof(struct sr_ethernet_hdr) - 
              sizeof(struct sr_ip_hdr));
      	    icmp_hdr_new->icmp_sum = icmp_cksum;

      	    /* send frame to next hop */
      	    printf("Send packet with NAT:\n");
      	    print_hdrs(sr_pkt, len);
      	    sr_send_packet(sr, sr_pkt, len, rtable->interface);
      	    free(arp_entry);
      	  }    
      	  /* arp miss */
      	  else {
      	    sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, 
      				 rtable->interface);
      	  }
      	  free(sr_pkt);
      	  free(rtable);
          free(nat_mapping);
	      }
      }
    }
    
    /* If it's a TCP packet*/
    else if (ip_hdr->ip_p == ip_protocol_tcp) {

      sr_tcp_hdr_t *tcp_hdr;
      tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + 
        sizeof(struct sr_ip_hdr));
      uint16_t original_tcp_src_port = tcp_hdr->port_src;
      uint16_t original_tcp_dst_port = tcp_hdr->port_dst;

      uint8_t flag = tcp_hdr->flag;
      int ack = flag & (1<<4);
      int syn = flag & (1<<1);          
      int fin = flag & 1;          

      /* if the tcp is from internal to external */
      if (strcmp(interface, INT_INTERFACE) == 0) {  

        /* lookup the longest prefix match */
        struct sr_rt *rtable = sr_longest_prefix_match(sr, original_ip_dst);

        /* if no match, icmp net unreachable */
        if (! rtable->gw.s_addr) {
          sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 0);
          return;
        }

        /* if match */          
        /* Look for nat mapping for corresponding src_ip and src_aux. */
        struct sr_nat_mapping *nat_mapping;
        nat_mapping = sr_nat_lookup_internal(sr->nat, original_ip_src, 
          original_tcp_src_port, nat_mapping_tcp, ip_hdr->ip_dst, tcp_hdr->port_dst, ack, syn, fin);
  
        /* Create new mapping if existing mapping not found.*/
        if (!nat_mapping) {
          nat_mapping = sr_nat_insert_mapping(sr->nat, original_ip_src, 
            original_tcp_src_port, nat_mapping_tcp, ip_hdr->ip_dst, tcp_hdr->port_dst, 1);
        }
        
        struct sr_if* o_iface = sr_get_interface(sr, EXT_INTERFACE);
        assert(o_iface);

        /* make a copy of the packet */
        uint8_t *sr_pkt = (uint8_t *)malloc(len);
        memcpy(sr_pkt, packet, len);

        /* check arp cache for next hop mac */
        struct sr_arpentry *arp_entry; 
        arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

        /*arp cache hit */
        if (arp_entry) {
          /* update ethernet header */
          ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
          memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
          memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN); 

          /* update ip header */
          ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
          ip_hdr->ip_ttl--;
          ip_hdr->ip_src = nat_mapping->ip_ext;
          bzero(&(ip_hdr->ip_sum), 2);  
          uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
          ip_hdr->ip_sum = ip_cksum;

          /* update tcp header */          
          tcp_hdr->port_src = nat_mapping->aux_ext;
          /* recalculate tcp chechsum */
          bzero(&(tcp_hdr->tcp_sum), 2);
          uint16_t tcp_cksum = cksum(tcp_hdr, len - 
            sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
          tcp_hdr->tcp_sum = tcp_cksum;          
          
          /* send frame to next hop */
          printf("Send packet:\n");
          print_hdrs(sr_pkt, len);
          sr_send_packet(sr, sr_pkt, len, EXT_INTERFACE);
          free(arp_entry);
          free(nat_mapping);
        }
        /* arp miss */
        else {
          sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, 
             EXT_INTERFACE);
        }
        free(sr_pkt);
        free(rtable); 
        free(nat_mapping);          
      }

      /* if the tcp is from external to internal */
      if (strcmp(interface, EXT_INTERFACE) == 0) {

        /* Look for nat mapping for corresponding dst_ip and dst_aux. */
        struct sr_nat_mapping *nat_mapping;
        nat_mapping = sr_nat_lookup_external(sr->nat, original_tcp_dst_port, 
          nat_mapping_icmp, ip_hdr->ip_src, tcp_hdr->port_src, ack, syn, fin);
        
        /* if no mapping, drop the packet */
        if (!nat_mapping) {
          fprintf(stderr , "** Error: No mapping found when forwarding tcp packet.");
          return;
        }

        /* lookup the longest prefix match */
        struct sr_rt *rtable = sr_longest_prefix_match(sr, nat_mapping->ip_int);

        /* if no match, icmp net unreachable */
        if (! rtable->gw.s_addr) {
          sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 0);
          return;
        }

        /* match */        
        struct sr_if* o_iface = sr_get_interface(sr, INT_INTERFACE);
        assert(o_iface);

        /* make a copy of the packet */
        uint8_t *sr_pkt = (uint8_t *)malloc(len);
        memcpy(sr_pkt, packet, len);

        /* check arp cache for next hop mac */
        struct sr_arpentry *arp_entry; 
        arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

        /*arp cache hit */
        if (arp_entry) {
          /* update ethernet header */
          ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
          memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
          memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN); 
        
          /* update ip header */
          ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
          ip_hdr->ip_ttl--;
          ip_hdr->ip_dst = nat_mapping->ip_int;
          bzero(&(ip_hdr->ip_sum), 2);  
          uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
          ip_hdr->ip_sum = ip_cksum;

          /* update tcp header */          
          tcp_hdr->port_dst = nat_mapping->aux_int;
          /* recalculate tcp chechsum */
          bzero(&(tcp_hdr->tcp_sum), 2);
          uint16_t tcp_cksum = cksum(tcp_hdr, len - 
            sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
          tcp_hdr->tcp_sum = tcp_cksum;          

          /* send frame to next hop */
          printf("Send packet:\n");
          print_hdrs(sr_pkt, len);
          sr_send_packet(sr, sr_pkt, len, INT_INTERFACE);
          free(arp_entry);
        }  
        /* arp miss */
        else {
          sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, 
             INT_INTERFACE);
        }
        free(sr_pkt);
        free(rtable);
        free(nat_mapping);
      }
    }
  }
 
  /* Routing without NAT. */
  else{
    uint32_t ip_dest;
    ip_dest = ip_hdr->ip_dst;
    
    /* lookup the longest prefix match */
    struct sr_rt *rtable = sr_longest_prefix_match(sr, ip_dest);

    /* if no match, icmp net unreachable */
    if (! rtable->gw.s_addr) {
      sr_icmp_dest_unreachable(sr, packet, len, interface, 3, 0);
      return;
    }
    /* match */
    else {   
      struct sr_if* o_iface = sr_get_interface(sr, rtable->interface);
      assert(o_iface);

      /* make a copy of the packet */
      uint8_t *sr_pkt = (uint8_t *)malloc(len);
      memcpy(sr_pkt, packet, len);

      /* check arp cache for next hop mac */
      struct sr_arpentry *arp_entry; 
      arp_entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

      /*arp cache hit */
      if (arp_entry) {
      	/* update ethernet header */
      	ethernet_hdr = (sr_ethernet_hdr_t *)sr_pkt;
      	memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN); 
      	memcpy(ethernet_hdr->ether_shost, o_iface->addr, ETHER_ADDR_LEN); 
            
      	/* update ip header */
      	ip_hdr = (sr_ip_hdr_t *)(sr_pkt + sizeof(struct sr_ethernet_hdr));
      	ip_hdr->ip_ttl--;
      	bzero(&(ip_hdr->ip_sum), 2);  
      	uint16_t ip_cksum = cksum(ip_hdr, 4*(ip_hdr->ip_hl));
      	ip_hdr->ip_sum = ip_cksum;  

      	/* send frame to next hop */
      	printf("Send packet:\n");
      	print_hdrs(sr_pkt, len);
      	sr_send_packet(sr, sr_pkt, len, rtable->interface);
      	free(arp_entry);
      }    
      /* arp miss */
      else {
        sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, rtable->interface);
      }
      free(sr_pkt);
      free(rtable);
    }
  }

  return;
} /* end sr_forward_ip_pkt */

/* Longest prefix match */
struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, uint32_t ip)
{
  assert(sr);
  assert(ip);
  struct sr_rt *rtable = (struct sr_rt *)malloc(sizeof(struct sr_rt));
  rtable->gw.s_addr = 0;
  rtable->mask.s_addr = 0;

  struct sr_rt *rt;
  for (rt = sr->routing_table; rt != NULL; rt = rt->next) {
    if (((ip & rt->mask.s_addr) == rt->dest.s_addr) && 
        (rt->mask.s_addr > rtable->mask.s_addr)) {
      memcpy(rtable, rt, sizeof(struct sr_rt));      
    }
  }

  return rtable;
} /* end sr_longest_prefix_match */


