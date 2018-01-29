/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * forward.c - an example using onvm. Forwards packets to a DST NF.
 ********************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "fp_pkt_helper.h"
#define NF_TAG "simple_forward"
#define Cycle_Control 12
uint32_t maglev_size;
uint32_t maglev_ndsts;
uint32_t *maglev_dst_ip;
uint16_t *maglev_dst_port;

uint32_t *maglev_table;
uint32_t *maglev_valid;
uint32_t **maglev_shuffle;
uint32_t *maglev_point;



/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

struct onvm_nf_LMAT *onvm_nf_LMAT;

/* number of package between each print */
static uint32_t print_delay = 100000000;


static uint32_t destination;

int
maglev_init(uint32_t size, uint32_t ndsts, uint32_t *dst_ip, uint16_t *dst_port);

uint32_t
maglev_hash(uint8_t protocol, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);

void
maglev_build(void);
/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                case 'd':
                        destination = strtoul(optarg, NULL, 10);
                        dst_flag = 1;
                        break;
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Simple Forward NF requires destination flag -d.\n");
                return -1;
        }

        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static uint64_t pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %"PRIu64"\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}


void
maglev_build(void){
    uint32_t linked = 0, count = 0, i;
    for(i = 0; i < maglev_size; ++i)
        maglev_table[i] = maglev_ndsts;
    for(i = 0; i < maglev_ndsts; ++i) {
        maglev_point[i] = 0;
        count += maglev_valid[i];
    }
    if(count == 0)
      return;
      
    for(; linked < maglev_size; )
        for(i = 0; i < maglev_ndsts && linked < maglev_size; ++i)
          if(maglev_valid[i]) {
              for(; maglev_table[maglev_shuffle[i][maglev_point[i]]] < maglev_ndsts; ++maglev_point[i]);
              ++linked;
              maglev_table[maglev_shuffle[i][maglev_point[i]]] = i;
        }
}

int
maglev_init(uint32_t size, uint32_t ndsts, uint32_t *dst_ip, uint16_t *dst_port) {
    maglev_size = size;
    maglev_ndsts = ndsts;
    maglev_dst_ip = dst_ip;
    maglev_dst_port = dst_port;

    maglev_table = malloc(size * 4);
    maglev_valid = malloc(ndsts);
    maglev_shuffle = malloc(ndsts * sizeof(void*));
    maglev_point = malloc(ndsts * 4);

    uint32_t i, j;
    for(i = 0; i < ndsts; ++i) {
        maglev_valid[i] = 1;
        maglev_shuffle[i] = malloc(size * 4);
        for(j = 0; j < size; ++j)
          maglev_shuffle[i][j] = j;
        for(j = 0; j < size; ++j) {
            uint32_t x = rand() % size;
            uint32_t y = rand() % size;
            uint32_t t = maglev_shuffle[i][x];
            maglev_shuffle[i][x] = maglev_shuffle[i][y];
            maglev_shuffle[i][y] = t;
        }
    }

    maglev_build();

    return 0;
}

uint32_t
maglev_hash(uint8_t protocol, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
    uint64_t value = protocol;
    value = ((value << 32) | src_ip) % maglev_size;
    value = ((value << 16) | src_port) % maglev_size;
    value = ((value << 32) | dst_ip) % maglev_size;
    value = ((value << 16) | dst_port) % maglev_size;
    return (uint32_t)value;
}





static int*
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
		
		int *LMAT = (int *)malloc(7*sizeof(int));
		static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }
		unsigned int hash_fid = NF_Get_FID_NOFP(pkt)%10000;
		LMAT[0] = hash_fid;

		nf_result result;
		packet_tuple* tuple;
		tuple = tuple_convert(pkt);
		uint32_t src_ip = 0;
		uint32_t dst_ip = 0;
		int i = 0;
		for(; i < 4; i ++)
		{
			src_ip = (src_ip << 8) + tuple->sip[3-i];
			dst_ip = (dst_ip << 8) + tuple->dip[3-i];
		}
		uint32_t hash = maglev_hash(tuple->proc, src_ip, tuple->sport, dst_ip, tuple->dport);
		uint32_t dst = maglev_table[hash];
		Modify(D_IP, maglev_dst_ip[dst], pkt);
		result.flag = 1;
		
		result.mod_type = ACTION_MODIFY;
		result.mod_field = FIELD_DSTIP;
		result.mod_value = maglev_dst_ip[dst];
		LMAT[1] = result.mod_type;//Modify_Type
		LMAT[2] = result.mod_field;//Modify_Field
		LMAT[3] = result.mod_value;//Modify_Value
		LMAT[4] = NO_State_Func;//0	
		LMAT[5] = nf_info->instance_id;//LMAT[4] means nf_id, manually set
		LMAT[6] = 0;//LMAT[5] == 0 means Ideal output(ret_act == 0)
		
		// meta->action = ONVM_NF_ACTION_TONF;
        // meta->destination = destination;
		meta->action = ONVM_NF_ACTION_OUT;
        meta->destination = 1;//Port_ID
        return LMAT;
		
		
		
}


int main(int argc, char *argv[]) {
        int arg_offset;

        const char *progname = argv[0];
		//printf("1\n");
        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        //printf("2\n");
        argc -= arg_offset;
        argv += arg_offset;
		//printf("3\n");
        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
		//printf("4\n");
		
		uint32_t ip[3] = {0x20000001,0x20000002,0x20000003};
		uint16_t port[3] = {0x0005,0x0006,0x0007};
    
		maglev_init(7, 3, ip , port);
	
        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
