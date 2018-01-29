/***************************Standard C library********************************/


#include <getopt.h>
#include <signal.h>


/*****************************Internal headers********************************/


#include "onvm_nflib.h"
#include "onvm_includes.h"
#include "onvm_sc_common.h"


/**********************************Macros*************************************/


// Number of packets to attempt to read from queue
#define PKT_READ_SIZE  ((uint16_t)32)

// Possible NF packet consuming modes
#define NF_MODE_UNKNOWN 0
#define NF_MODE_SINGLE 1
#define NF_MODE_RING 2

#define ONVM_NO_CALLBACK NULL


typedef int(*pkt_handler)(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta);
typedef int(*callback_handler)(void);

int
fp_onvm_nflib_run_callback(
        struct onvm_nf_info* info,
        pkt_handler handler,
        callback_handler callback)
{
        void *pkts[PKT_READ_SIZE];
        int ret;


        /* Don't allow conflicting NF modes */
        if (nf_mode == NF_MODE_RING) {
                return -1;
        }
        nf_mode = NF_MODE_SINGLE;

        printf("\nClient process %d handling packets\n", info->instance_id);

        /* Listen for ^C and docker stop so we can exit gracefully */
        signal(SIGINT, onvm_nflib_handle_signal);
        signal(SIGTERM, onvm_nflib_handle_signal);

        printf("Sending NF_READY message to manager.............\n");
        ret = onvm_nflib_nf_ready(info);
        if (ret != 0) rte_exit(EXIT_FAILURE, "Unable to message manager\n");
		
        printf("[Press Ctrl-C Ctrl-C  to quit ...]\n");
		//printf("%d\n", keep_running);
        for (; keep_running;) {
				//printf("L\n");
                onvm_nflib_dequeue_messages();
				
				onvm_nflib_dequeue_packets(pkts, info, handler);
				//printf("L+1\n");
                
                if (callback != ONVM_NO_CALLBACK) {
                        keep_running = !(*callback)() && keep_running;
                }
        }

        // Stop and free
        onvm_nflib_cleanup();

        return 0;
}

int
fp_onvm_nflib_run(struct onvm_nf_info* info, pkt_handler handler) {
        return fp_onvm_nflib_run_callback(info, handler, ONVM_NO_CALLBACK);
}