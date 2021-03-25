wget http://fast.dpdk.org/rel/dpdk-21.02.tar.xz
tar xvf dpdk-21.02.tar.xz
cd dpdk-21.02/
meson build
cd build
ninja
cd ..
