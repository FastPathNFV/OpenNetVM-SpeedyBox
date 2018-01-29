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
#define Cycle_Control 10


/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

struct onvm_nf_LMAT *onvm_nf_LMAT;

/* number of package between each print */
static uint32_t print_delay = 10000000;

static uint32_t destination;

nat_acl acl[NAT_ACL_LENGTH] = {
	{{192,168,0,1},{10,0,0,1},1,1,2,0},
	{{192,168,31,2},{10,0,0,2},1,1,2,0},
	{{192,168,31,3},{10,0,0,3},1,1,2,0},
	{{10,0,0,1},{192,168,31,1},2,1,2,0},
	{{10,0,0,1},{192,168,31,2},2,1,2,0},
	{{10,0,0,1},{192,168,31,3},2,1,2,0},
	{{192,168,31,1},{10,0,0,1},0,2,6,2},
	{{192,168,31,2},{10,0,0,2},0,3,7,2},
	{{192,168,31,3},{10,0,0,3},0,4,8,2},
	{{192,168,31,3},{10,0,0,3},0,5,9,2}
};

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

static int*
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
		int *LMAT = (int *)malloc(7*sizeof(int));
		static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }
        // meta->action = ONVM_NF_ACTION_TONF;
        // meta->destination = destination;
		
		meta->action = ONVM_NF_ACTION_OUT;
        meta->destination = pkt->port;
		
		nf_result result;
		result = nat(pkt,acl);
		
		int hash_fid;
		hash_fid = NF_Get_FID_NOFP(pkt);	
		
		LMAT[0] = hash_fid;
		if(result.flag == 0)
		{
			LMAT[1] = ACTION_NULL;
			LMAT[2] = 0;
			LMAT[3] = 0;
		}
		else{
			LMAT[1] = result.mod_type;
			LMAT[2] = result.mod_field;
			LMAT[3] = result.mod_value;
			int para = 0;
			if((result.mod_field) % 2 == 0)
			{
				para = result.mod_field * 2 + 12;
			}else{
				para = result.mod_field * 1 + 19;
			}
			Modify(para, result.mod_value, pkt);
		}

		LMAT[4] = 0;
		LMAT[5] = nf_info->instance_id;//LMAT[4] means nf_id, manually set
		LMAT[6] = 0;//LMAT[5] == 0 means Ideal output(ret_act == 0)

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
		//int lala = 0;
		// for(;lala < NAT_ACL_LENGTH;lala++)
		// {
			// printf("%d,%d,%d,%d %d,%d,%d,%d %x %u %u %x\n",acl[lala].ori_ip[0],acl[lala].ori_ip[1],acl[lala].ori_ip[2],acl[lala].ori_ip[3],
					// acl[lala].tra_ip[0],acl[lala].tra_ip[1],acl[lala].tra_ip[2],acl[lala].tra_ip[3],acl[lala].ip_flag,acl[lala].ori_port,acl[lala].tra_port,acl[lala].port_flag);
		// }
		
        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
