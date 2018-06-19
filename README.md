OpenNetVM-SpeedyBox
==

OpenNetVM-SpeedyBox is a NFV platform based on openNetVM, witch is an open source version of the NetVM platform described in [NSDI 2014 paper][nsdi04] and [HotMiddlebox 2016][hotmiddlebox16]. openNetVM-SpeedyBox and openNetVM are installed and used in the same way. 


Installing
--

You can follow the instrutions in [openNetVM-FastPath Installation][install] to install our system.

Using openNetVM-FastPath
--
  1. Run Manager:
    - Run the manager in dynamic mode with the following command.  We are using a corelist here to manually pin the manager to specific cores, a portmask to decide which NIC ports(here we use port 0 and 1) to use, and configuring it display manager statistics to stdout:
      - `# ./go.sh 0,1,2,3,4,5,6 1 -p 3 -s stdout`
  2. Start NFs:
    - First, we'll start one firewall NF and have it forward to service ID 2.
      - `# ./examples/fw_fp/go.sh 7 1 2`
    - Second, start up 1 load balancer NF and have it forward to NIC port 1.
      - `# ./examples/speed_tester/go.sh 8 2 2`
  3. We now have a NF service chain with a firewall and followed by a load balancer.


[hotmiddlebox16]: http://faculty.cs.gwu.edu/timwood/papers/16-HotMiddlebox-onvm.pdf
[nsdi04]: http://faculty.cs.gwu.edu/timwood/papers/14-NSDI-netvm.pdf
[install]: docs/Install.md
[openNetVM]: https://github.com/sdnfv/openNetVM
