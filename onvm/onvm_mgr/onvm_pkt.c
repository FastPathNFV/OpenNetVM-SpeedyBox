/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
 *            2010-2014 Intel Corporation. All rights reserved.
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
 ********************************************************************/


/******************************************************************************
                                 onvm_pkt.c

            This file contains all functions related to receiving or
            transmitting packets.

******************************************************************************/


#include "onvm_mgr.h"
#include "onvm_pkt.h"
#include "onvm_nf.h"
#include "onvm_init.h"
#include "onvm_pkt_helper.h"
#include "onvm_common.h"
#include "fastpath_pkt.h"
#include "sa_snort.h"
#include <inttypes.h>

#include <rte_branch_prediction.h>
#include <rte_mbuf.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>



/**********************FastPath Global Variables**************************/
//extern int LMAT_bef_cons[(NUM_OF_NF) + 1][6];
extern uint32_t hash_fid;
extern int cpa[4];
extern int *tmp_cpa;
extern int state_val;
MAT_Map LMAT[NUM_OF_NF][NUM_OF_FLOW], GMAT[NUM_OF_FLOW];
URT_Map URT[NUM_OF_FLOW];
uint32_t op_hash[PACKET_READ_SIZE];
int OP_LMAT_bef_cons[NUM_OF_FLOW][1 + 3 * NUM_OF_NF];
int FP_LMAT_bef_cons[NUM_OF_FLOW][1 + 3 * NUM_OF_NF];

uint64_t fp_total_cont;
uint64_t op_total_cont;

/****************************FP Snort Variables****************************/
extern int file_line;      /* current line being processed in the rules file */
extern int rule_count;
extern Rule *current;      /* util ptr for the current rule */
extern Rule *PassList;     /* List of Pass Rules */
extern Rule *LogList;      /* List of Log Rules */
extern Rule *AlertList;    /* List of Alert Rules */
PrintIP pip;


/**********************Internal Functions Prototypes**************************/


/*
 * Function to send packets to one port after processing them.
 *
 * Input : a pointer to the tx queue
 *
 */
static void
onvm_pkt_flush_port_queue(struct thread_info *tx, uint16_t port);


/*
 * Function to send packets to one NF after processing them.
 *
 * Input : a pointer to the tx queue
 *
 */
static void
onvm_pkt_flush_nf_queue(struct thread_info *thread, uint16_t nf_id);


/*
 * Function to enqueue a packet on one port's queue.
 *
 * Inputs : a pointer to the tx queue responsible
 *          the number of the port
 *          a pointer to the packet
 *
 */
inline static void
onvm_pkt_enqueue_port(struct thread_info *tx, uint16_t port, struct rte_mbuf *buf);


/*
 * Function to enqueue a packet on one NF's queue.
 *
 * Inputs : a pointer to the tx queue responsible
 *          the number of the port
 *          a pointer to the packet
 *
 */
inline static void
onvm_pkt_enqueue_nf(struct thread_info *thread, uint16_t dst_service_id, struct rte_mbuf *pkt);


/*
 * Function to process a single packet.
 *
 * Inputs : a pointer to the tx queue responsible
 *          a pointer to the packet
 *          a pointer to the NF involved
 *
 */
inline static void
onvm_pkt_process_next_action(struct thread_info *tx, struct rte_mbuf *pkt, struct onvm_nf *nf);


/*
 * Helper function to drop a packet.
 *
 * Input : a pointer to the packet
 *
 * Ouput : an error code
 *
 */
static int
onvm_pkt_drop(struct rte_mbuf *pkt);


/**********************************Interfaces*********************************/



void
onvm_pkt_process_rx_batch(struct thread_info *rx, struct rte_mbuf *pkts[], uint16_t rx_count, struct rte_ring *tx_ring) {

		uint16_t i;
        struct onvm_pkt_meta *meta;
       
		int snort_seq;
		void *bufs_fp[PACKET_READ_SIZE];
		struct rte_mbuf *bufs_op[PACKET_READ_SIZE];
		int fp_pkt_count = 0;
		int op_pkt_count = 0;
		int op_pkt_lmat_update_con = 0;
		int op_pkt_lmat_update_flag = 0;
		
		
        if (rx == NULL || pkts == NULL)
                return;
		Modify_FID(rx_count,pkts);
		snort_seq = -1;
        for (i = 0; i < rx_count; i++) 
		{
			meta = (struct onvm_pkt_meta*) &(((struct rte_mbuf*)pkts[i])->udata64);
			meta->src = 0;
			meta->chain_index = 0;
			//hash_fid = Get_FID(pkts,i);
			hash_fid = NF_Get_FID_Chain(pkts[i]);
			if(GMAT[hash_fid].flag == 0)
			{
				op_total_cont++;
				int for_con3 = 0;
				op_pkt_lmat_update_flag = 0;
				for(; for_con3 < op_pkt_lmat_update_con; for_con3++)
				{
					if(op_hash[for_con3] == hash_fid)
					{
						op_pkt_lmat_update_flag = 1;
						break;
					}
				}
				if(op_pkt_lmat_update_flag == 0)
				{
					op_hash[op_pkt_lmat_update_con] = hash_fid;
					op_pkt_lmat_update_con ++;
				}
				op_pkt_count ++;
				bufs_op[op_pkt_count] = pkts[i];
				meta->action = ONVM_NF_ACTION_TONF;
				meta->destination = 1;
				(meta->chain_index)++;
				onvm_pkt_enqueue_nf(rx, meta->destination, pkts[i]);
			}
			else{
				fp_total_cont++;
				bufs_fp[fp_pkt_count] = pkts[i];
				execute_GMAT_rule(hash_fid, cpa, snort_seq, pkts[i]);
				if(cpa[3] != VALUE_NULL)
				{
					if(cpa[0]!=0)
					{
						Modify(S_IP,cpa[0],pkts,i);
					}
					if(cpa[1]!=0)
					{
						Modify(S_Port,cpa[1],pkts,i);
					}
					if(cpa[2]!=0)
					{
						Modify(D_IP,cpa[2],pkts,i);
					}
					if(cpa[3]!=0)
					{
						Modify(D_Port,cpa[3],pkts,i);
					}
				}
				struct onvm_pkt_meta* meta;
				meta = onvm_get_pkt_meta((struct rte_mbuf*)pkts[i]);
				meta->destination = 1;
				meta->action = ONVM_NF_ACTION_OUT;
				fp_pkt_count ++;
			}
			
		}
		if(fp_pkt_count > 0)
			rte_ring_enqueue_bulk(tx_ring, bufs_fp, fp_pkt_count);
		if(op_pkt_lmat_update_con > 0)
		{
			int for_con1 = 0;
			int op_complete_count = 0;
			onvm_pkt_flush_all_nfs(rx);
			while(1)
			{
				onvm_nf_check_LMAT();
				for(for_con1 = 0;for_con1 < op_pkt_lmat_update_con;for_con1 ++)
				{
					if((OP_LMAT_bef_cons[op_hash[for_con1]][0] == NUM_OF_NF))
					{
						if((GMAT[op_hash[for_con1]].flag == 1))
						{
							op_complete_count ++;
						}
						else{
							
							/*--------------NF 1 Definition Begin-------------*/
							LMAT_add_rule(LMAT[0], op_hash[for_con1], OP_LMAT_bef_cons[op_hash[for_con1]][1], OP_LMAT_bef_cons[op_hash[for_con1]][2], OP_LMAT_bef_cons[op_hash[for_con1]][3], NF1_state_action);
							/*--------------NF 1 Definition End-------------*/
							
							/*--------------NF 2 Definition Begin-------------*/
							//LMAT_add_rule(LMAT[1], op_hash[for_con1], OP_LMAT_bef_cons[op_hash[for_con1]][4], OP_LMAT_bef_cons[op_hash[for_con1]][5], OP_LMAT_bef_cons[op_hash[for_con1]][6], NF1_state_action);
							/*--------------NF 2 Definition End-------------*/
							
							
							/*--------------NF 3 Definition Begin-------------*/
							//LMAT_add_rule(LMAT[2], op_hash[for_con1], OP_LMAT_bef_cons[op_hash[for_con1]][7], OP_LMAT_bef_cons[op_hash[for_con1]][8], OP_LMAT_bef_cons[op_hash[for_con1]][9], NF1_state_action);
							/*--------------NF 3 Definition End-------------*/

							
							/*--------------GMAT: State Action Parallel Execution-------------*/
							SA_parallel_execution(op_hash[for_con1], snort_seq, bufs_op[for_con1]);
										
							/*--------------GMAT: Packet Action Consolidation -------------*/
							tmp_cpa = PA_consolidation(op_hash[for_con1]);
							cpa[0] = tmp_cpa[0];
							cpa[1] = tmp_cpa[1];
							cpa[2] = tmp_cpa[2];
							cpa[3] = tmp_cpa[3];
							add_rule_to_GMAT(op_hash[for_con1], cpa);
							op_complete_count ++;
						}
						if((op_complete_count == rx_count)||(op_complete_count == op_pkt_lmat_update_con))
							break;
					}
				}
				if(op_complete_count == op_pkt_lmat_update_con)
				{
					break;
				}	
			}
		}
}


void
onvm_pkt_process_tx_batch(struct thread_info *tx, struct rte_mbuf *pkts[], uint16_t tx_count, struct onvm_nf *nf) {
        uint16_t i;
        struct onvm_pkt_meta *meta;

        if (tx == NULL || pkts == NULL || nf == NULL)
                return;
        for (i = 0; i < tx_count; i++) {
                meta = (struct onvm_pkt_meta*) &(((struct rte_mbuf*)pkts[i])->udata64);
                meta->src = nf->instance_id;
                if (meta->action == ONVM_NF_ACTION_DROP) {
                        nf->stats.act_drop += !onvm_pkt_drop(pkts[i]);
                } else if (meta->action == ONVM_NF_ACTION_NEXT) {
                        nf->stats.act_next++;
                        onvm_pkt_process_next_action(tx, pkts[i], nf);
                } else if (meta->action == ONVM_NF_ACTION_TONF) {
                        nf->stats.act_tonf++;
                        onvm_pkt_enqueue_nf(tx, meta->destination, pkts[i]);
                } else if (meta->action == ONVM_NF_ACTION_OUT) {
                        nf->stats.act_out++;
                        onvm_pkt_enqueue_port(tx, meta->destination, pkts[i]);
                } else {
                        printf("ERROR invalid action : this shouldn't happen.\n");
                        onvm_pkt_drop(pkts[i]);
                        return;
                }
        }
}


void
onvm_pkt_flush_all_ports(struct thread_info *tx) {
        uint16_t i;

        if (tx == NULL)
                return;

        for (i = 0; i < ports->num_ports; i++)
                onvm_pkt_flush_port_queue(tx, ports->id[i]);
}


void
onvm_pkt_flush_all_nfs(struct thread_info *tx) {
        uint16_t i;

        if (tx == NULL)
                return;

        for (i = 0; i < MAX_NFS; i++)
                onvm_pkt_flush_nf_queue(tx, i);
}

void
onvm_pkt_drop_batch(struct rte_mbuf **pkts, uint16_t size) {
        uint16_t i;

        if (pkts == NULL)
                return;

        for (i = 0; i < size; i++)
                rte_pktmbuf_free(pkts[i]);
}


/****************************Internal functions*******************************/


static void
onvm_pkt_flush_port_queue(struct thread_info *tx, uint16_t port) {
        uint16_t i, sent;
        volatile struct tx_stats *tx_stats;

        if (tx == NULL)
                return;

        if (tx->port_tx_buf[port].count == 0)
                return;

        tx_stats = &(ports->tx_stats);
        sent = rte_eth_tx_burst(port,
                                tx->queue_id,
                                tx->port_tx_buf[port].buffer,
                                tx->port_tx_buf[port].count);
        if (unlikely(sent < tx->port_tx_buf[port].count)) {
                for (i = sent; i < tx->port_tx_buf[port].count; i++) {
                        onvm_pkt_drop(tx->port_tx_buf[port].buffer[i]);
                }
                tx_stats->tx_drop[port] += (tx->port_tx_buf[port].count - sent);
        }
        tx_stats->tx[port] += sent;

        tx->port_tx_buf[port].count = 0;
}


static void
onvm_pkt_flush_nf_queue(struct thread_info *thread, uint16_t nf_id) {
        uint16_t i;
        struct onvm_nf *nf;

        if (thread == NULL)
                return;

        if (thread->nf_rx_buf[nf_id].count == 0)
                return;

        nf = &nfs[nf_id];

        // Ensure destination NF is running and ready to receive packets
        if (!onvm_nf_is_valid(nf))
                return;

        if (rte_ring_enqueue_bulk(nf->rx_q, (void **)thread->nf_rx_buf[nf_id].buffer,
                        thread->nf_rx_buf[nf_id].count) != 0) {
                for (i = 0; i < thread->nf_rx_buf[nf_id].count; i++) {
                        onvm_pkt_drop(thread->nf_rx_buf[nf_id].buffer[i]);
                }
                nf->stats.rx_drop += thread->nf_rx_buf[nf_id].count;
        } else {
                nf->stats.rx += thread->nf_rx_buf[nf_id].count;
        }
        thread->nf_rx_buf[nf_id].count = 0;
}


inline static void
onvm_pkt_enqueue_port(struct thread_info *tx, uint16_t port, struct rte_mbuf *buf) {

        if (tx == NULL || buf == NULL)
                return;


        tx->port_tx_buf[port].buffer[tx->port_tx_buf[port].count++] = buf;
        if (tx->port_tx_buf[port].count == PACKET_READ_SIZE) {
                onvm_pkt_flush_port_queue(tx, port);
        }
}


inline static void
onvm_pkt_enqueue_nf(struct thread_info *thread, uint16_t dst_service_id, struct rte_mbuf *pkt) {
        struct onvm_nf *nf;
        uint16_t dst_instance_id;


        if (thread == NULL || pkt == NULL)
                return;

        // map service to instance and check one exists
        dst_instance_id = onvm_nf_service_to_nf_map(dst_service_id, pkt);
        if (dst_instance_id == 0) {
                onvm_pkt_drop(pkt);
                return;
        }

        // Ensure destination NF is running and ready to receive packets
        nf = &nfs[dst_instance_id];
        if (!onvm_nf_is_valid(nf)) {
                onvm_pkt_drop(pkt);
                return;
        }

        thread->nf_rx_buf[dst_instance_id].buffer[thread->nf_rx_buf[dst_instance_id].count++] = pkt;
        if (thread->nf_rx_buf[dst_instance_id].count == 32) {//PACKET_READ_SIZE
                onvm_pkt_flush_nf_queue(thread, dst_instance_id);
        }
}


inline static void
onvm_pkt_process_next_action(struct thread_info *tx, struct rte_mbuf *pkt, struct onvm_nf *nf) {

        if (tx == NULL || pkt == NULL || nf == NULL)
                return;

        struct onvm_flow_entry *flow_entry;
        struct onvm_service_chain *sc;
        struct onvm_pkt_meta *meta = onvm_get_pkt_meta(pkt);
        int ret;

        ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (ret >= 0) {
                sc = flow_entry->sc;
                meta->action = onvm_sc_next_action(sc, pkt);
                meta->destination = onvm_sc_next_destination(sc, pkt);
        } else {
                meta->action = onvm_sc_next_action(default_chain, pkt);
                meta->destination = onvm_sc_next_destination(default_chain, pkt);
        }

        switch (meta->action) {
                case ONVM_NF_ACTION_DROP:
                        // if the packet is drop, then <return value> is 0
                        // and !<return value> is 1.
                        nf->stats.act_drop += !onvm_pkt_drop(pkt);
                        break;
                case ONVM_NF_ACTION_TONF:
                        nf->stats.act_tonf++;
                        onvm_pkt_enqueue_nf(tx, meta->destination, pkt);
                        break;
                case ONVM_NF_ACTION_OUT:
                        nf->stats.act_out++;
                        onvm_pkt_enqueue_port(tx, meta->destination, pkt);
                        break;
                default:
                        break;
        }
        (meta->chain_index)++;
}


/*******************************Helper function*******************************/


static int
onvm_pkt_drop(struct rte_mbuf *pkt) {
        rte_pktmbuf_free(pkt);
        if (pkt != NULL) {
                return 1;
        }
        return 0;
}
