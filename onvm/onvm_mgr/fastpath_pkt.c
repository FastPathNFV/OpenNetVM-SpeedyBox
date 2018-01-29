#include "onvm_mgr.h"
#include "onvm_pkt.h"
#include "onvm_nf.h"
#include "onvm_init.h"
#include "onvm_pkt_helper.h"
#include "onvm_common.h"
#include "fastpath_pkt.h"
#include <inttypes.h>

#include <rte_branch_prediction.h>
#include <rte_mbuf.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

extern MAT_Map LMAT[NUM_OF_NF][NUM_OF_FLOW], GMAT[NUM_OF_FLOW];
extern URT_Map URT[NUM_OF_FLOW];
int flag_PA = -1; //记录最后Consolidation的PA是modify还是drop
int state_val = 0;
extern int hash_fid;
extern pthread_t thread[NUM_OF_NF]; //threads
void * thread_return[NUM_OF_NF];

 __attribute__ ((gnu_inline)) inline void
Pkt_View(struct rte_mbuf ** bufs, int nb_rx) {
	int t, i;
	for (t=0;t<nb_rx;++t) {
		unsigned char * d = PktData(bufs[t]);
//		d = d + 256;
		//printf("%d %d %d %d\n",bufs[t]->data_off, bufs[t]->data_len,(unsigned char *)(bufs[t]->buf_addr) - (unsigned char *)bufs[t], (unsigned char *)rte_mbuf_data_dma_addr(bufs[t])-(unsigned char *)bufs[t]);
		puts("\nPkt:\n");
		printf("Dst MAC: ");
		printMac(d);
		printf("Src MAC: ");
		printMac(d+6);
		unsigned char * ipd = d+14;
		printf("IPv%d len: %d ",*ipd>>4, (*(ipd+2)<<8)|(*(ipd+3)));
		printf("src IP: ");
		printIP(ipd+12);
		printf("dst IP: ");
		printIP(ipd+16);
		printf("protocol: %d, serv.: %x", *(ipd + 9), *(ipd + 1));
		printf("\n\x1b[0m");
		for (i = 0; i < (((*(ipd+2)<<8)|(*(ipd+3))) + 14); ++i) printf("\x1b[33m%02x \x1b[0m",d[i]);
		printf("\n\x1b[0m");
	}

}



 __attribute__ ((gnu_inline)) inline void
printMac(unsigned char * d) {
	int i;
	for (i=0;i<6;++i)
		printf("\x1b[33m%02x \x1b[0m", d[i]);
}

 __attribute__ ((gnu_inline)) inline void
printIP(unsigned char * d) {
	printf("\x1b[33m%3d.%3d.%3d.%3d \x1b[0m",*d,*(d+1),*(d+2),*(d+3));
}

void
print_PA(MAT_Map LMAT[], int FID){
    printf("%d\t%d\t%d\t%d\n", LMAT[FID].PA[0], LMAT[FID].PA[1], LMAT[FID].PA[2], LMAT[FID].PA[3]);
}

void
PktTag(struct rte_mbuf* pkt)
{
	unsigned char * d = PktData(pkt);
	d = d + 14;
	*d = *d + 128;
}

void
Modify_FID(int Pkt_Num, struct rte_mbuf ** bufs){
	int i;
	for(i = 0; i < Pkt_Num ;i++)
	{
		unsigned char * d = PktData(bufs[i]);

		uint32_t hash_fid = Hash_FID(d);
		//printf("\nModify_FID:%d\n",hash_fid);
		int j;
		
		for(j = 0;j < 4;j++)
		{	
			uint32_t hash_fidd = hash_fid;
			*(d + 14 + 4 + j) = hash_fidd >> ((3-j)*8);
			//*(d + 14 + 8) = 1;
		}		
	}	
}

// uint32_t
// Hash_FID(unsigned char * d){
	// uint32_t hash_fid = 0;
	// int i;
	// d = d + 14;
	// hash_fid = (uint32_t)*(d +15);
	// if(hash_fid > 127)
		// hash_fid = hash_fid - 128;
	// // printf("Hash_FID---:%d\n",(uint32_t)*(d +15));
	// // printf("Hash_FID:%d\n",hash_fid);
	// for(i = 1;i < 2;i++)
	// {
		// hash_fid = (hash_fid << 8);
		// hash_fid = hash_fid + *(d + 15 +i * 4);
		// // printf("Hash_FID---:%d\n",(uint32_t)*(d + 15 +i * 4));
		// // printf("Hash_FID:%d\n",hash_fid);
	// }
	// for(i = 0;i < 2;i++)
	// {
		// hash_fid = (hash_fid << 8);
		// hash_fid = hash_fid + *(d + 21 +i * 2);
		// // printf("Hash_FID---:%d\n",(uint32_t)*(d + 21 +i * 2));
		// // printf("Hash_FID:%d\n",hash_fid);
	// }
	// return hash_fid;
// }

uint32_t
Hash_FID(unsigned char * d){
	uint32_t hash_fid = 0;
	int i;
	d = d + 14;
	hash_fid = (uint32_t)*(d +20);
	if(hash_fid > 127)
		hash_fid = hash_fid - 128;
	// printf("Hash_FID---:%d\n",(uint32_t)*(d +15));
	// printf("Hash_FID:%d\n",hash_fid);
	for(i = 1;i < 2;i++)
	{
		hash_fid = (hash_fid << 8);
		hash_fid = hash_fid + *(d + 20 + 1);
		// printf("Hash_FID---:%d\n",(uint32_t)*(d + 15 +i * 4));
		// printf("Hash_FID:%d\n",hash_fid);
	}
	for(i = 0;i < 2;i++)
	{
		hash_fid = (hash_fid << 8);
		hash_fid = hash_fid + *(d + 22 +i * 1);
		// printf("Hash_FID---:%d\n",(uint32_t)*(d + 21 +i * 2));
		// printf("Hash_FID:%d\n",hash_fid);
	}
	return hash_fid;
}


uint32_t
Get_FID(struct rte_mbuf ** bufs, uint16_t n){
	unsigned char * d = PktData(bufs[n]);
	uint32_t hash_fid = 0;
	int i =0;
	hash_fid = hash_fid + *(d + 14 + 4);
	for(i=1;i<4;i++)
	{
		
//		printf("step_hash_fid:%d\n",hash_fid);
		hash_fid = (hash_fid << 8) + *(d + 14 + 4 + i);
	}
	return hash_fid;
}

uint32_t
NF_Get_FID_Chain(struct rte_mbuf * bufs){
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

void
Modify(uint16_t Field, int Value, struct rte_mbuf * b[],int Pkt_ID)
{
	uint16_t i;
	unsigned char * d = PktData(b[Pkt_ID]);
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
//	printf("\nSIP:\n");
//	printIP(d+14+12);
//	printf("DIP:\n");
//	printIP(d+14+16);
//	printf("\nSport:%x%x,\nDport:%x%x\n",*(d+14+20),*(d+14+21),*(d+14+22),*(d+14+23));
}

void
LMAT_add_rule(MAT_Map LMAT[], int FID, int packet_action, int field, int value, SA stateaction){
    //int PA_val, field_val;
//    printf("LMAT:1\n");
    LMAT[FID].PA[0] = packet_action;
    LMAT[FID].PA[1] = field;
    LMAT[FID].PA[2] = value;
	LMAT[FID].stateAction = stateaction;

		

    if(packet_action == ACTION_DROP){
    	LMAT[FID].PA[3] = FIELD_NULL;
    }
//    printf("LMAT:2\n");
}

void
LMAT_add_rule_snort(MAT_Map LMAT[], int FID, int packet_action, int field, int value, SA_SNORT stateaction){
    //int PA_val, field_val;
//    printf("LMAT:1\n");
    LMAT[FID].PA[0] = packet_action;
    LMAT[FID].PA[1] = field;
    LMAT[FID].PA[2] = value;
	LMAT[FID].stateAction_snort = stateaction;
    if(packet_action == ACTION_DROP){
    	LMAT[FID].PA[3] = FIELD_NULL;
    }
//    printf("LMAT:2\n");
}








void
register_URT(int FID, int* state_address, int condition_threshold, int update_action[3]){
    URT[FID].state_address = state_address;
    URT[FID].condition_threshold = condition_threshold;
    URT[FID].update_action = update_action;
//    printf("Regi_URT:1\n");
}

int*
PA_consolidation(int FID){ //2017-8-26 19:08:39 JYM：目前的算法就只考虑了Modify和Drop两种Paction Action
    int i;
    // int cpa[4] = {0,0,0,0};
	int* cpa = (int *)malloc(4);
	int* record_modify = (int *) malloc(4);
	for(i=0;i<4;i++){
		record_modify[i] = 0;
		cpa[i] = 0;
	}
	// printf("--1\n");
    // int record_modify[NUM_OF_FIELD] = {0};//排除了Drop的情况后，剩下要记录modify情况下的field-value键值对，相当于记录每个位置的
    for(i = 0; i < NUM_OF_NF; i ++){
		// printf("LMAT[i][FID].PA[0]:%d\n",LMAT[i][FID].PA[0]);
        if (LMAT[i][FID].PA[0]==ACTION_DROP){
//            cpa = calloc(4, sizeof(int));
            cpa[0] = ACTION_DROP;
            cpa[1] = FIELD_NULL;
            cpa[2] = VALUE_NULL;
            cpa[3] = VALUE_NULL;
            flag_PA = ACTION_DROP;
            return cpa;
        }
		else if (LMAT[i][FID].PA[0]==ACTION_NULL){
			continue;
		}
		// printf("--45\n");
        record_modify[LMAT[i][FID].PA[1]] = LMAT[i][FID].PA[2];//由于是modify操作，每次会覆盖前面的结果
    }
	// printf("--2\n");
   // printf("\n----------------------------------------------\nConsolidation Results:\n" );
   // printf("SRCIP\tSRCPORT\tDSTIP\tDSTPORT\n");
   // printf("0x%x\t0x%x\t0x%x\t0x%x\n", record_modify[FIELD_SRCIP], record_modify[FIELD_SRCPORT], record_modify[FIELD_DSTIP], record_modify[FIELD_DSTPORT]);
   // printf("----------------------------------------------\n" );
    flag_PA = ACTION_MODIFY;
    return record_modify;
}

void
check_URT(MAT_Map LMAT[], int FID){ //register update rule
    int condition_threshold = URT[FID].condition_threshold;
    int* state_address = URT[FID].state_address;
    int* update_action = URT[FID].update_action;
    if (URT[FID].is_updated==0 && *state_address > condition_threshold) { // match
        LMAT[FID].PA[0] = update_action[0];
        LMAT[FID].PA[1] = update_action[1];
        LMAT[FID].PA[2] = update_action[2];
        URT[FID].is_updated = 1;
//        printf("action of FID=%d has been updated to %d\n", FID, update_action[0]);

    }
    int *cpa;
    cpa = PA_consolidation(FID);
    add_rule_to_GMAT(FID, cpa);
}

void
SA_parallel_execution(int FID, int snort_seq, struct rte_mbuf* pkt){ //单线程只执行最长时间的SF

	//int i;
	if(snort_seq < 0)//no snort
	{
		execute_SA(LMAT[SF_ID], FID);
	}else{//snort_seq >= 0, snort exists
		execute_SA_snort(LMAT[snort_seq], FID, pkt);
	}	
}

// void
// SA_parallel_execution(int FID, int snort_seq, struct rte_mbuf* pkt){ //单线程

	// int i;
	// if(snort_seq < 0)//no snort
	// {
		// for(i = 0;i < NUM_OF_NF;i ++)
		// {
			// execute_SA(LMAT[i], FID);
		// }
	// }else{//snort_seq > 0, snort exists
		// for(i = 0;i < NUM_OF_NF;i ++)
		// {
			// if(i == snort_seq)
			// {
				// execute_SA_snort(LMAT[i], FID, pkt);
			// }
			// else{
				// execute_SA(LMAT[i], FID);
			// }
		// }
	// }	
// }




// void
// SA_parallel_execution(int FID, int snort_seq, struct rte_mbuf* pkt){ //多线程-不断creat版
	// int i =0;
	// uint64_t cycle_start = rte_get_timer_cycles();

	// if(snort_seq < 0)//no snort
	// {
		// for(;i < NUM_OF_NF;i++)
		// {
			// pthread_create(&thread[i], NULL, thread1, &FID);
		// }
	// }else{//snort exist
		// pthread_create(&thread[0], NULL, thread_snort1, &pkt);
		// //pthread_create(&thread[1], NULL, thread_snort1, &pkt);
		// //pthread_create(&thread[i], NULL, thread1, &FID);
	// }
	// int ret;
	// for(i = 0;i < NUM_OF_NF;i++)
	// {
		// // pthread_join(thread[i],&thread_return[NUM_OF_NF]);
		// ret = pthread_join(thread[i],NULL);
		// if(ret != 0)
			// printf("State Function #%d finish error\n",i);
	// }
	// uint64_t cycle_end = rte_get_timer_cycles();
	// printf("cycle SA_parallel_execution: %lu \n", (cycle_end - cycle_start));
// }

// void
// SA_parallel_execution(int FID, int snort_seq, struct rte_mbuf* pkt){ ////多线程-多核痴痴等待版
	// int i =0;
	// uint64_t cycle_start = rte_get_timer_cycles();

	// if(snort_seq < 0)//no snort
	// {
		// for(;i < NUM_OF_NF;i++)
		// {
			// //pthread_create(&thread[i], NULL, thread1, &FID);
		// }
	// }else{//snort exist
		// //pthread_create(&thread[0], NULL, thread_snort1, &pkt);
		// //pthread_create(&thread[1], NULL, thread_snort1, &pkt);
		// //pthread_create(&thread[i], NULL, thread1, &FID);
	// }
	// int ret;
	// for(i = 0;i < NUM_OF_NF;i++)
	// {
		// // pthread_join(thread[i],&thread_return[NUM_OF_NF]);
		// //ret = pthread_join(thread[i],NULL);
		// if(ret != 0)
			// printf("State Function #%d finish error\n",i);
	// }
	// uint64_t cycle_end = rte_get_timer_cycles();
	// //printf("cycle SA_parallel_execution: %lu \n", (cycle_end - cycle_start));
// }
/**************************************************
	static int thread_nopkt_X(void * FID)
	State Function without pkt payload Read/Write
	Duplicate if necessary
**************************************************/

// static int thread_nopkt_1(void * FID)
// {
	// execute_SA(LMAT[0], *(int *)FID);
	// return (void *)1;
// }
/**************************************************
	static int thread_pkt_X(void * FID)
	State Function without pkt payload Read/Write
	Duplicate if necessary
**************************************************/


// static int thread_pkt_1(void * pkt)
// {
	// //struct rte_mbuf* pkts = (struct rte_mbuf*)pkt;
	// execute_SA_snort(LMAT[0], hash_fid, (struct rte_mbuf*)pkt);
	// return (void *)1;
// }

void
execute_SA(MAT_Map LMAT[], int FID){
//	printf("execute_SA:1\n");
    SA s_action;
//    printf("execute_SA:2\n");
    s_action = LMAT[FID].stateAction;
//    printf("execute_SA:3\n");
    s_action(FID);
//    printf("execute_SA:4\n");
}

void
execute_SA_snort(MAT_Map LMAT[], int FID, struct rte_mbuf* pkt){
//	printf("execute_SA:1\n");
    SA_SNORT s_action;
//    printf("execute_SA:2\n");
	FID =  hash_fid;
    s_action = LMAT[FID].stateAction_snort;
//    printf("execute_SA:3\n");
    s_action(pkt);
//    printf("execute_SA:4\n");
}

uint32_t delay(uint32_t x , uint32_t control){
  uint32_t res = 1;
  for(uint32_t i = 0; i < control; ++i)
   res *= x ^ (x & 1);
  return res;
}

void
add_rule_to_GMAT(int FID, int *cpa){
	GMAT[FID].flag = 1;
	GMAT[FID].PA[0] = cpa[0];
	GMAT[FID].PA[1] = cpa[1];
	GMAT[FID].PA[2] = cpa[2];
	GMAT[FID].PA[3] = cpa[3];
}

void
execute_GMAT_rule(int FID, int CPA[], int snort_seq, struct rte_mbuf* pkt){
	SA_parallel_execution(FID, snort_seq, pkt);
	int hyc_i = 0;
	for (hyc_i = 0;hyc_i < 4;hyc_i++)
	{
		CPA[hyc_i] = GMAT[FID].PA[hyc_i];
	}
//	CPA = GMAT[FID].PA;
//	printf("\nexecute_GMAT_rule2\n");
}

// void
// execute_GMAT_rule(int FID, int CPA[]){
	// //SA_parallel_execution(FID, snort_seq, pkt);
	// int hyc_i = 0;
	// for (hyc_i = 0;hyc_i < 4;hyc_i++)
	// {
		// CPA[hyc_i] = GMAT[FID].PA[hyc_i];
	// }
// //	CPA = GMAT[FID].PA;
// //	printf("\nexecute_GMAT_rule2\n");
// }


void
NF1_state_action(int FID){
    //uint64_t cycle_start = rte_get_timer_cycles();
	uint32_t temp = FID;
	temp = temp + 1;
	//printf("NF1: state action is printf,%d\n",FID);
	//uint64_t cycle_end = rte_get_timer_cycles();
	//printf("cycle NF1_state_action: %lu \n", (cycle_end - cycle_start));
	// state_val = FID;
    // while (state_val<20) {
        // state_val++;
        // check_URT(LMAT[0], FID);
        // //print_PA(LMAT[0], FID);
    // }
}

void
NF2_state_action(int FID){

    printf("NF2: state action is printf,%d\n",FID);
}


