[openNetVM-FastPath]
==

About
--
openNetVM-FastPath is a NFV platform based on openNetVM, witch is an open source version of the NetVM platform described in [NSDI 2014 paper][nsdi04] and [HotMiddlebox 2016][hotmiddlebox16]. openNetVM-FastPath and openNetVM are installed and used in the same way. If you are familiar with openNetVM, you will finish installing and get started with openNetVM-FastPath easily. Installing and Using openNetVM-FastPath are followed, which are mainly copied from original page [openNetVM][openNetVM].


Installing
--
openNetVM-FastPath and openNetVM are installed in the same way. To install openNetVM-FastPath, please see the [openNetVM Installation][install] guide for a thorough walkthrough.

Using openNetVM-FastPath
--
  1. Run Manager:
    - Run the manager in dynamic mode with the following command.  We are using a corelist here to manually pin the manager to specific cores, a portmask to decide which NIC ports to use, and configuring it display manager statistics to stdout:
      - `# ./go.sh 0,1,2,3,4,5,6 1 -p 3 -s stdout
  2. Start NFs:
    - First, start up to n-1 simple_forward NFs.  For simplicity, we'll start one firewall NF.
      - `# ./examples/fw_fp/go.sh 7 1 1`
    - Second, start up 1 load balancer NF and have it forward to service ID 2.
      - `# ./examples/speed_tester/go.sh 14 2 2`
  3. We now have a NF service chain with firewall and load balancer.


[hotmiddlebox16]: http://faculty.cs.gwu.edu/timwood/papers/16-HotMiddlebox-onvm.pdf
[nsdi04]: http://faculty.cs.gwu.edu/timwood/papers/14-NSDI-netvm.pdf
[install]: docs/Install.md
[examples]: docs/Examples.md
[openNetVM]: https://github.com/sdnfv/openNetVM
