#ifndef _FP_PKT_HELPER_
#define _FP_PKT_HELPER_
#include <stdint.h>
#define NUM_OF_ACTION 4
#define ACTION_NULL -1
#define ACTION_MODIFY 4
#define ACTION_DROP 1
#define ACTION_ENCAP 2
#define ACTION_DECAP 3

#define NUM_OF_FIELD 4
#define FIELD_NULL -1
#define FIELD_SRCIP 0
#define FIELD_SRCPORT 1
#define FIELD_DSTIP 2
#define FIELD_DSTPORT 3
#define VALUE_NULL -1
#define S_IP 12
#define D_IP 16
#define _FID 4
#define S_Port 20
#define D_Port 22

#define IS_State_Func 1
#define NO_State_Func 0

#define BALCKLIST_MATCH 1
#define BLACKLIST_LENGTH 10
#define NAT_ACL_LENGTH 10
#define match(a,b) ((a == b)? 1:0)


#define PKT_NUM 111900
#define FID_NUM 5750

typedef struct five_tuple{
	unsigned char sip[4];
	unsigned char dip[4];
	short sport;
	short dport;
	char proc;
}packet_tuple;

typedef struct Nat_Acl{
	unsigned char ori_ip[4];
	unsigned char tra_ip[4];
	char ip_flag;//0:no change,1:src_ip,2:dst_ip
	short ori_port;
	short tra_port;
	char port_flag;//0:no change,1:src_port,2:dst_port
}nat_acl;

typedef struct Nat_Result{
	unsigned int flag;//0:drop,1:modify
	unsigned int mod_type;
	unsigned int mod_field;
	unsigned int mod_value;
}nf_result;//;

typedef struct fpt{
	uint16_t num;
	uint64_t cycle;
}FPt;

uint32_t
NF_Get_FID(struct rte_mbuf * bufs);

uint32_t
NF_Get_FID_NOFP(struct rte_mbuf * bufs);

unsigned int
firewall_blk(struct rte_mbuf * bufs, packet_tuple* blacklist, int list_length);

unsigned int
fw_list_match(packet_tuple* tuple, packet_tuple blacklist);

packet_tuple *
tuple_convert(struct rte_mbuf * bufs);

int
nat_list_match(packet_tuple* tuple, nat_acl acl);

nf_result
nat(struct rte_mbuf * bufs, nat_acl* acl);

unsigned int
ip_convert(unsigned char ip[4]);

void
Modify(unsigned short Field, int Value, struct rte_mbuf * pkt);

unsigned int
is_state_func(struct rte_mbuf * pkt);

#endif  // _FP_PKT_HELPER_