#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/uip.h"
#include "net/uip-ds6.h"
#include "net/rpl/rpl.h"

#include "httpd-ws.h"

#include "rplstats.h"

#include <stdio.h>
#include <string.h>

PROCESS(rplstats, "rpl stats");
AUTOSTART_PROCESSES(&rplstats);

#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15])

struct etimer et_ping;

static const char ct_json[] = "application/json";
/*[2002:3239:614b:000b:0000:0000:0000:0000]*/
static char host[64] = "[aaaa::1]";
static uint16_t port = 80;
static char path[80] = "/rplstats";

extern uip_ds6_nbr_t uip_ds6_nbr_cache[];
extern uip_ds6_route_t uip_ds6_routing_table[];

static char buf[HTTPD_OUTBUF_SIZE];
static uint8_t buf_lock = 0;

static
PT_THREAD(send_buf(struct httpd_ws_state *s))
{
	memcpy(s->outbuf, buf, HTTPD_OUTBUF_SIZE);
	s->outbuf_pos = strlen(buf);
	buf_lock = 0;

	PSOCK_BEGIN(&s->sout);
	if(s->outbuf_pos > 0) {
		SEND_STRING(&s->sout, s->outbuf, s->outbuf_pos);
		s->outbuf_pos = 0;
	}
	PSOCK_END(&s->sout);
}



uint16_t create_rank_msg(char *buf)
{
	rpl_dag_t *dag;
	uint8_t n = 0;
	buf_lock = 1;
	n += sprintf(&(buf[n]),"{\"rank\":%d}",dag->rank);
	buf[n] = 0;
	PRINTF("buf: %s\n", buf);
	return n;
}

uint16_t create_parent_msg(char *buf, rpl_parent_t *parent, uint8_t preffered)
{
	uint8_t n = 0;

	n += sprintf(&(buf[n]), "{\"adr\":\"%04x%04x%04x%04x\",", 
				 parent->addr.u16[4],
				 parent->addr.u16[5],
				 parent->addr.u16[6],
				 parent->addr.u16[7]);
	n += sprintf(&(buf[n]), "\"pref\":");
	if(preffered == 1) {
		n += sprintf(&(buf[n]), "true,");
	} else {
		n += sprintf(&(buf[n]), "false,");
	}
	n += sprintf(&(buf[n]), "\"etx\":%d}", parent->mc.obj.etx);

	buf[n] = 0;
	PRINTF("buf: %s\n", buf);
	return n;
}

static struct httpd_ws_state *s;
static rpl_dag_t *dag;
static rpl_parent_t *parent;
static uint8_t first;

PROCESS_THREAD(rplstats, ev, data)
{
  uip_ipaddr_t *addr;
  PROCESS_BEGIN();

  etimer_set(&et_ping, 5 * CLOCK_SECOND);

  while(1) {
	  uint16_t content_len;
	  PROCESS_WAIT_EVENT();

	  if(etimer_expired(&et_ping)) 
	  {
		  dag = rpl_get_any_dag();
		  if(dag != NULL) {		  
			  PRINTF("post!\n\r");
			  PRINTF("prefix info, len %d\n\r", dag->prefix_info.length);
			  PRINT6ADDR(&(dag->prefix_info.prefix));
			  PRINTF("\n\r");
			  addr = &(dag->prefix_info.prefix);
			  /* assume 64 bit prefix for now */
			  sprintf(host, "[%02x%02x:%02x%02x:%02x%02x:%02x%02x::1]", 
				  ((u8_t *)addr)[0], ((u8_t *)addr)[1], 
				  ((u8_t *)addr)[2], ((u8_t *)addr)[3], 
				  ((u8_t *)addr)[4], ((u8_t *)addr)[5], 
				  ((u8_t *)addr)[6], ((u8_t *)addr)[7]);
			  PRINTF("host: %s\n\r", host);

			  content_len = create_rank_msg(buf);
			  s = httpd_ws_request(HTTPD_WS_POST, host, NULL, port,
					       path, ct_json,
					       content_len, send_buf);
			  while (s->state != 0) { PROCESS_PAUSE(); }
			  
			  first = 1;
		  	  for (parent = dag->preferred_parent; parent != NULL; parent = parent->next) {
		  	  	  content_len = create_parent_msg(buf, parent, first);
		  	  	  s = httpd_ws_request(HTTPD_WS_POST, host, NULL, port,
		  	  			   path, ct_json,
		  	  			   content_len, send_buf);
				  while (s->state != 0) { PROCESS_PAUSE(); }
		  	  	  first = 0;
		  	  }

		  }
		  
		  etimer_set(&et_ping, 5 * CLOCK_SECOND);

	  }
  }
  
  PROCESS_END();
}

