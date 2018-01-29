#include "onvm_pkt_helper.h"
#include "fp_pkt_helper.h"
#include "onvm_common.h"

#include <inttypes.h>

#include <rte_branch_prediction.h>
#include <rte_mbuf.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <rte_common.h>



/****************************************************************************
 *
 * Function: DecodeEthPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
 
uint32_t
NF_Get_FID(struct rte_mbuf * bufs){
	unsigned char * d = PktData(bufs);
	uint32_t hash_fid = 0;
	int i = 0;
	hash_fid = hash_fid + *(d + 14 + 4);
	for(i=1;i<4;i++)
	{
		
//		printf("step_hash_fid:%d\n",hash_fid);
		hash_fid = (hash_fid << 8) + *(d + 14 + 4 + i);
	}
	//printf("\nGet_FID:%d\n",hash_fid);
	return hash_fid;
}
uint32_t
NF_Get_FID_NOFP(struct rte_mbuf * bufs){
	unsigned char * d = PktData(bufs);
	uint32_t hash_fid = 0;
	//int i = 0;
	hash_fid = hash_fid + *(d + 14 + 22);
	hash_fid = hash_fid * 256 + *(d + 14 + 23);
	// for(i=1;i<4;i++)
	// {
		
		// //printf("step_hash_fid:%d\n",hash_fid);
		// hash_fid = (hash_fid << 8) + *(d + 14 + 20 + i);
	// }
	//printf("\nGet_FID:%d\n",hash_fid);
	return hash_fid;
}


unsigned int
firewall_blk(struct rte_mbuf * bufs, packet_tuple* blacklist, int list_length)
{
	packet_tuple* tuple;
	tuple = tuple_convert(bufs);
	// printf("%d,%d,%d,%d %d,%d,%d,%d %u %u %x\n",tuple->sip[0],tuple->sip[1],tuple->sip[2],tuple->sip[3],
			// tuple->dip[0],tuple->dip[1],tuple->dip[2],tuple->dip[3],tuple->sport,tuple->dport,tuple->proc);
	int num = 0;
	int flag = 0;
	for(;num < list_length;num++)
	{
		flag = fw_list_match(tuple, blacklist[num]);
		//printf("No:%d,flag:%d\n",num,flag);
		if(flag == BALCKLIST_MATCH)
			return ACTION_DROP;//1 means DROP
	}
	return ACTION_NULL;//-1
}


unsigned int
fw_list_match(packet_tuple* tuple, packet_tuple blacklist)
{
	if(
	match(tuple->sport , blacklist.sport)&&
	match(tuple->dport , blacklist.dport)&&
	match(tuple->proc , blacklist.proc)&&
	match(tuple->sip[0] , blacklist.sip[0])&&
	match(tuple->sip[1] , blacklist.sip[1])&&
	match(tuple->sip[2] , blacklist.sip[2])&&
	match(tuple->sip[3] , blacklist.sip[3])&&
	match(tuple->dip[0] , blacklist.dip[0])&&
	match(tuple->dip[1] , blacklist.dip[1])&&
	match(tuple->dip[2] , blacklist.dip[2])&&
	match(tuple->dip[3] , blacklist.dip[3])
	)
		return 1;
	else
		return 0;
}


packet_tuple *
tuple_convert(struct rte_mbuf * bufs)
{
	struct ipv4_hdr* ip_hdr;
	ip_hdr = onvm_pkt_ipv4_hdr(bufs);
	struct tcp_hdr* tcp ;
	tcp = onvm_pkt_tcp_hdr(bufs);
	packet_tuple* tuple = (packet_tuple *)malloc(sizeof(packet_tuple));
	
	tuple->sport = rte_be_to_cpu_16(tcp->src_port);
	tuple->dport = rte_be_to_cpu_16(tcp->dst_port);
	tuple->proc = ip_hdr->next_proto_id;
	tuple->sip[0] = ip_hdr->src_addr & 0xFF;
	tuple->sip[1] = (ip_hdr->src_addr >> 8) & 0xFF;
	tuple->sip[2] = (ip_hdr->src_addr >> 16) & 0xFF;
	tuple->sip[3] = (ip_hdr->src_addr >> 24) & 0xFF;
	tuple->dip[0] = ip_hdr->dst_addr & 0xFF;
	tuple->dip[1] = (ip_hdr->dst_addr >> 8) & 0xFF;
	tuple->dip[2] = (ip_hdr->dst_addr >> 16) & 0xFF;
	tuple->dip[3] = (ip_hdr->dst_addr >> 24) & 0xFF;
	return tuple;	
}

nf_result
nat(struct rte_mbuf * bufs, nat_acl* acl)
{
	packet_tuple* tuple;
	tuple = tuple_convert(bufs);
	nf_result result;
	int num = 0;
	int flag = 0;
	for(;num < NAT_ACL_LENGTH;num++)
	{
		flag = nat_list_match(tuple, acl[num]);
		//printf("No:%d,flag:%d\n",num,flag);
		if(flag > 0)
			break;//>0 means Modify
	}
	switch(flag)
	{
		case 1:
			result.flag = 1;
			result.mod_type = ACTION_MODIFY;
			result.mod_field = FIELD_SRCPORT;
			result.mod_value = acl[num].tra_port;
			return result;
		case 2:
			result.flag = 1;
			result.mod_type = ACTION_MODIFY;
			result.mod_field = FIELD_DSTPORT;
			result.mod_value = acl[num].tra_port;
			return result;
		case 10:
			//printf("10\n");
			result.flag = 1;
			result.mod_type = ACTION_MODIFY;
			result.mod_field = FIELD_SRCIP;
			result.mod_value = ip_convert(acl[num].tra_ip);
			//printf("%d %d %d %d\n",result.flag, result.mod_type, result.mod_field, result.mod_value);
			return result;
		case 20:
			result.flag = 1;
			result.mod_type = ACTION_MODIFY;
			result.mod_field = FIELD_DSTIP;
			result.mod_value = ip_convert(acl[num].tra_ip);
			return result;
		default:
			result.flag = 0;
			result.mod_type = 0;
			result.mod_field = 0;
			result.mod_value = 0;
			return result;
	}
	//return result;
}

unsigned int
ip_convert(unsigned char ip[4])
{
	unsigned int ip_value = 0;
	int num = 0;
	for(;num < 4;num++)
	{
		ip_value = (ip_value << 8) + ip[num]; 
	}
	return ip_value;
}

int
nat_list_match(packet_tuple* tuple, nat_acl acl)
{
	switch(acl.ip_flag)
	{
		case 0://port
			switch(acl.port_flag)
			{
				case 1://
					if(match(tuple->sport , acl.tra_port))
						return 1;
					else
						return 0;
				case 2:
					if(match(tuple->dport , acl.tra_port))
						return 2;
					else
						return 0;
				default:
					return 0;
			}
		case 1:
			if( match(tuple->sip[0] , acl.ori_ip[0])&&
				match(tuple->sip[1] , acl.ori_ip[1])&&
				match(tuple->sip[2] , acl.ori_ip[2])&&
				match(tuple->sip[3] , acl.ori_ip[3]))
				return 10;
			else
				return 0;
		case 2:
			if(	match(tuple->dip[0] , acl.ori_ip[0])&&
				match(tuple->dip[1] , acl.ori_ip[1])&&
				match(tuple->dip[2] , acl.ori_ip[2])&&
				match(tuple->dip[3] , acl.ori_ip[3]))
				return 20;
			else
				return 0;
	}
	return 0;	
}



void
Modify(unsigned short Field, int Value, struct rte_mbuf * pkt)
{
	unsigned short i;
	unsigned char * d = PktData(pkt);
	if(Field < 20 && Field >10)
	{
		for(i=0;i<4;i++)
		{
			unsigned char Value_Trans = Value >> ((3-i)*8);//int->unsigned char
			*(d+14+Field+i) = Value_Trans;
			// printf("%d\n",Value_Trans);
		}
	}
	else{
		for(i=0;i<2;i++)
		{
			unsigned char Value_Trans = Value >> (i*8);//int->unsigned char
			*(d+14+Field+1-i) = Value_Trans;
		}

	}
}

unsigned int
is_state_func(struct rte_mbuf * pkt)
{
	unsigned char * d = PktData(pkt);
	d = d + 14;
	if(((*d)&(uint8_t)128) == 128)
	{
		//*d = *d -128;
		return 1;
	}else
	{
		return 0;
	}
}
















