#ifndef _FASTPATH_PKT_H_
#define _FASTPATH_PKT_H_


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
#define NUM_OF_FLOW 10000
#define S_IP 12
#define D_IP 16
#define _FID 4
#define S_Port 20
#define D_Port 22
#define IS_OP 0
#define IS_FP 1
#define SF_ID 0


#define PKT_NUM 91625
#define FID_NUM 5750
#define NUM_OF_NF 1
/****************************FP Packet Structure****************************/
typedef void (*SA)(int);
typedef void (*SA_SNORT)(struct rte_mbuf* pkt);

typedef struct{
	int flag;//flag == 1 means PF,flag == 0 means OP
    int PA[4];
    SA stateAction;
	SA_SNORT stateAction_snort;
	uint64_t processing_cycle;
}MAT_Map;

typedef struct{ //JYM: 目前的实现假设每个流最多往URT注册一个update规则，因此相关的state最多就一个。另外，目前state都统一用int变量表示，实际上更严格的来说应该用泛型实现。
    int is_updated;
    int condition_threshold;
    int* state_address;
    int* update_action;
}URT_Map;

typedef struct fpt{
	uint16_t num;
	uint64_t cycle;
}FPt;


 __attribute__ ((gnu_inline))
inline unsigned char *
PktData(struct rte_mbuf * x);

 __attribute__ ((gnu_inline))
inline void
printMac(unsigned char * d);

 __attribute__ ((gnu_inline))
inline void
printIP(unsigned char * d);

 __attribute__ ((gnu_inline))
inline void
Pkt_View(struct rte_mbuf ** bufs, int nb_rx);

void
print_PA(MAT_Map LMAT[], int FID);

uint32_t
NF_Get_FID_Chain(struct rte_mbuf * bufs);

uint32_t
delay(uint32_t x , uint32_t control);

void
PktTag(struct rte_mbuf* pkt);

void
Modify_FID(int Pkt_Num, struct rte_mbuf ** bufs);

uint32_t
Hash_FID(unsigned char * d);

uint32_t
Get_FID(struct rte_mbuf ** bufs, uint16_t n);

void
Modify(uint16_t Field, int Value, struct rte_mbuf * b[],int Pkt_ID);

void
LMAT_add_rule(MAT_Map LMAT[], int FID, int packet_action, int field, int value, SA stateaction);

void
LMAT_add_rule_snort(MAT_Map LMAT[], int FID, int packet_action, int field, int value, SA_SNORT stateaction);

void
execute_SA(MAT_Map LMAT[], int FID);

void
execute_SA_snort(MAT_Map LMAT[], int FID, struct rte_mbuf* pkt);

void
register_URT(int FID, int* state_address, int condition_threshold, int update_action[3]);

int*
PA_consolidation(int FID);

void
check_URT(MAT_Map LMAT[], int FID);

void
SA_parallel_execution(int FID, int snort_seq, struct rte_mbuf* pkt);


void *thread1(void * FID);

void *thread2(void * FID);

void *thread3(void * FID);

void *thread4(void * FID);

void *thread5(void * FID);

void *thread_snort1(void * pkt);



void
add_rule_to_GMAT(int FID, int *cpa);

// void
// execute_GMAT_rule(int FID, int CPA[]);

void
execute_GMAT_rule(int FID, int CPA[], int snort_seq, struct rte_mbuf* pkt);

void
NF1_state_action(int FID);

void
NF2_state_action(int FID);


#endif  // _FASTPATH_PKT_H_