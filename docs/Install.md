# openNetVM-FastPath Installation

This guide helps you build and install openNetVM-FastPath.

1. Check System
--

1. Make sure your NIC is supported by Intel DPDK by comparing the following command's ouptput against DPDK's [supported NIC list](http://dpdk.org/doc/nics).

    ```sh
    lspci | awk '/net/ {print $1}' | xargs -i% lspci -ks %
    ```

2.  Check what operating system you have by typing:
    ```sh
    uname -a
    ```
    your Kernel version should be higher than 2.6.33.

3. Install dependencies
    ```sh
    sudo apt-get install build-essential linux-headers-$(uname -r) git
    ```
4. Assure your kernel suppors uio
    ```sh
    locate uio
    ```

2. Setup Repositories
--

1. Download source code
    ```sh
    git clone https://github.com/FastPathNFV/OpenNetVM-FastPath.git
    ```

2. Initialize DPDK submodule
    ```sh
    git submodule init && git submodule update
    ```

 **From this point forward, this guide assumes that you are working out of the openNetVM-FastPath source directory.**

3. Set up Environment
--

1. Set environment variable ONVM_HOME to the path of the openNetVM-FastPath source directory.
    ```sh
    echo export ONVM_HOME=$(pwd) >> ~/.bashrc
    ```

2. List DPDK supported architectures:
    ```sh
    ls dpdk/config/
    ```

3. Set environment variable RTE_SDK to the path of the DPDK library.  Make sure that you are in the DPDK directory
    ```sh
    echo export RTE_SDK=$(pwd) >> ~/.bashrc
    ```

4. Set environment variable RTE_TARGET to the target architecture of your system.  This is found in step 3.1
    ```sh
    echo export RTE_TARGET=x86_64-native-linuxapp-gcc  >> ~/.bashrc
    ```

5. Set environment variable ONVM_NUM_HUGEPAGES and ONVM_NIC_PCI.

    ONVM_NUM_HUGEPAGES is a variable specifies how many hugepages are reserved by the user, default value of this is 1024, which could be set using:
    ```sh
    echo export ONVM_NUM_HUGEPAGES=1024 >> ~/.bashrc
    ```

    ONVM_NIC_PCI is a variable that specifies NIC ports to be bound to DPDK.  If ONVM_NIC_PCI is not specified, the default action is to bind all non-active 10G NIC ports to DPDK.
    ```sh
    export ONVM_NIC_PCI=" 07:00.0 07:00.1 "
    ```
6. Source your shell rc file to set the environment variables:
    ```sh
    source ~/.bashrc
    ```

7. Disable ASLR since it makes sharing memory with NFs harder:
   ```sh
    sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"
    ```

8. Configure and compile DPDK
--

1. Run the [install script](../scripts/install.sh) to compile DPDK and configure hugepages.
    ```sh¬
    cd scripts
    ./install.sh
    ```

    The [install script](../scripts/install.sh) will automatically run the [environment setup script](../scripts/setup_environment.sh), which configures your local environment.  This should be run once for every reboot, as it loads the appropraite kernel modules and can bind your NIC ports to the DPDK driver.

5. Run DPDK HelloWorld Application
--

1. Enter DPDK HelloWorld directory and compile the application:

    ```sh
    cd dpdk/examples/helloworld
    make
    ```

2. Run the HelloWorld application

    ```sh
    sudo ./build/helloworld -l 0,1 -n 1
    ```

    If the last line of output is as such, then DPDK works

    ```sh
    hello from core 1
    hello from core 0
    ```

6. Make and test openNetVM-FastPath
--

1. Compile openNetVM-FastPath manager and libraries

    ```sh
    cd onvm
    make
    ```

2. Compile example NFs

    ```sh
    cd examples/NF_Names
    make
    ```
