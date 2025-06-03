## Install L25GC+ on Ubuntu 22.04

For the AN and DN, you can directly run the setup scripts in the L25GC-plus repository:

```bash
cd ./L25GC-plus/scripts 
./setup.sh <ue|dn>
```

---

## 1. Run the setup script

Run `./L25GC-plus/scripts/install_ubuntu22.sh` to install L25GC+.

```bash
cd scripts
./install_ubuntu22.sh
```


## 2. Patch DPDK build files

Apply the following changes to address build warnings and linker issues:

<details>
<summary><code>onvm/onvm-upf/dpdk/kernel/linux/igb_uio/Makefile</code></summary>

```diff
 MODULE_CFLAGS += -I$(SRCDIR) --param max-inline-insns-single=100
 MODULE_CFLAGS += -I$(RTE_OUTPUT)/include
-MODULE_CFLAGS += -Winline -Wall -Werror
+MODULE_CFLAGS += -Winline -Wall -Wno-error=implicit-fallthrough -Wno-implicit-fallthrough
 MODULE_CFLAGS += -include $(RTE_OUTPUT)/include/rte_config.h
```
</details>

<details>
<summary><code>onvm/onvm-upf/dpdk/mk/toolchain/gcc/rte.vars.mk</code></summary>

```diff
 WERROR_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual
 WERROR_FLAGS += -Wformat-nonliteral -Wformat-security
 WERROR_FLAGS += -Wundef -Wwrite-strings -Wdeprecated
+WERROR_FLAGS += -Wno-implicit-fallthrough

 ifeq ($(RTE_DEVEL_BUILD),y)
 WERROR_FLAGS += -Werror
```
</details>

---

## 3. Modify and rebuild ONVM

Apply the following patches to ONVM to fix build and linking issues:

<details>
<summary><code>onvm/onvm-upf/onvm/onvm_mgr/Makefile</code></summary>

```diff
 CFLAGS += -O3 $(USER_FLAGS)
+CFLAGS += -fcommon
 CFLAGS += -I$(SRCDIR)/../ -I$(SRCDIR)/../onvm_nflib/ -I$(SRCDIR)/../lib/
 CFLAGS += -I$(ONVM_HOME)/onvm/logger/
 CFLAGS += -I$(ONVM_HOME)/onvm/utlt/
```
</details>

<details>
<summary><code>onvm/onvm-upf/scripts/install.sh</code></summary>

```diff
 #  - Set $ONVM_SKIP_FSTAB to not add huge fs to /etc/fstab
 
+export RTE_DEVEL_BUILD=n
 #Print a table with enviromental variable locations
 echo "----------------------------------------"
 echo "ONVM Environment Variables:"
```
</details>

<details>
<summary><code>onvm/build_testbed.sh</code></summary>

```diff
 # sudo apt-get install -y python3
 # sudo apt-get install -y libnuma-dev
 
-git clone https://github.com/nycu-ucr/onvm-upf.git
+# git clone https://github.com/nycu-ucr/onvm-upf.git
 cd $workdir/onvm-upf
 git submodule sync
 git submodule update --init
```
</details>

---

## 4. ReInstall

The changes in submodule are now complete.  
You should modify `L25GC-plus/install.sh` then run `L25GC-plus/install.sh` to finish the installation.


<details>
<summary><code>L25GC-plus/install.sh</code></summary>

```diff
 git submodule update --init
 
 cd $HOME
-git clone https://github.com/nycu-ucr/onvm.git
+#git clone https://github.com/nycu-ucr/onvm.git
```
</details>

### Run install script
```bash
cd ~/L25GC-plus
./install.sh
```

---

## 5. Fix ONVM_NFLIB Multiple Definition Issue

If you encounter `multiple definition` errors during compilation, follow these steps to modify `onvm_nflib.c` and recompile.

### Error Example

![onvm_nflib.c](./images/problem.png)

### Solution

Edit `onvm/onvm_nflib/onvm_nflib.c` and change the global variable definitions to `extern` as shown below:

<details>
<summary><code>onvm/onvm-upf/onvm/onvm_nflib/onvm_nflib.c</code></summary>


```diff
// Shared data for host port information
-struct port_info *ports;
+extern struct port_info *ports;

// Shared data for core information
-struct core_status *cores;
+extern struct core_status *cores;

// Shared data from server. We update statistics here
-struct onvm_nf *nfs;
+extern struct onvm_nf *nfs;

/* Shared data for onvm config */
-struct onvm_configuration *onvm_config;
+extern struct onvm_configuration *onvm_config;

/* Flag to check if shared core mutex sleep/wakeup is enabled */
-uint8_t ONVM_NF_SHARE_CORES;
+extern uint8_t ONVM_NF_SHARE_CORES;
```

</details>

### Recompile

After making the changes, recompile `onvm-upf`:

```bash
cd ~/onvm/onvm-upf/
make
```
