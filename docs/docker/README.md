## Intallation in docker ##

This L25GC-plus is Release 15

### clone nycu-ucr/onvm (in local)
```
sudo apt install libnuma-dev
git clone https://github.com/nycu-ucr/onvm.git
cd onvm
git checkout opensource
source ./build_testbed.sh
```
press Y/N to bind DPDK NICs, you need at least 2 NICs to run L25GC+ or use command to bind DPDK NICs

```
sudo ip link set <interface> down
sudo ~/onvm/onvm-upf/dpdk/usertools/dpdk-devbind.py -s
sudo ~/onvm/onvm-upf/dpdk/usertools/dpdk-devbind.py -b igb_uio <PCI>
```

### pull and run docker images
```
sudo apt install docker.io
sudo docker pull linpoyi/l25gc-plus_v0
sudo docker run -it --privileged --name test_v1 linpoyi/l25gc-plus_v0
```

### setup huge pages in container(in container's bash)
```
su linpoyi #password: wirelab020
cd ~/onvm/onvm-upf/dpdk/usertools
./dpdk-setup.sh
49 #setup huge pages
1024 #number of huge pages
62 # exit script
```

### pull and run mongodb images(in local new terminal)
```
sudo docker pull mongo
sudo docker run --name db mongo
```

### check docker network
```
docker network inspect bridge
```
find the ipv4 address of container "db"

### modified config in L25GC+(back to L25GC+'s bash)
```
vim ~/L25GC-plus/config/nrfcfg.yaml
```
change "MongoDBUrl" from 127.0.0.1 to the ip address of db container




## Running L25GC+(in container's bash) ##

1. **Run ONVM Manager**
    ```bash
    cd ~/onvm
    ./run_manager.sh
    ```
2. **Run UPF-U** (new terminal)
    ```bash
    cd ~/onvm/onvm-upf/5gc/upf_u_complete
    sudo ./go.sh 1
    ```
3. **Run UPF-C** (new terminal)
    ```bash
    cd ~/onvm/onvm-upf/5gc/upf_c_complete
    sudo ./go.sh 2
    ```
4. **Run 5GC Network Functions (NFs)** (new terminal)

    ```bash
    cd ~/L25GC-plus
    ./run.sh
    ```
5. **Stop L25GC+**

    ```bash
    cd ~/onvm
    ./force_kill.sh
    ```

