# # cambricon mlu driver适配说明

## 1.1驱动源码目录介绍

```shell
.
├── attr
├── binn
├── cambricon-mlu-driver-ubuntu20.04-dkms-mkdeb
├── cnmon
├── commu
├── config
├── core
├── device
├── dkms
├── dkms.conf
├── domain
├── expmnt
├── fw
├── gdma
├── i2c
├── include
├── ipcm
├── Kbuild
├── lib		    # 设备固件，不同硬件有不同的固件，驱动加载前需要拷贝到/lib/firmware/cambricon
├── load
├── load_auto   # 自动加载脚本，会完成Firmware拷贝到系统目录
├── load_host_vf
├── load_with_sriov
├── log
├── lpm
├── Makefile  #直接make -j32就可以编译，遇见编译问题直接修改，建议使用git formart-patch产生patch给我们合入主线，这样在未来版本里就可以带上修改。
├── mcc
├── mcu
├── mig
├── mm
├── monitor
├── noc
├── nor
├── plat
├── proc
├── README
├── README.md
├── sbts
├── smlu
├── tools
├── unload
└── unload_auto	// 使用load_auto加载，对应使用unload_auto卸载
```

## 1.2 驱动源码编译

驱动安装，首先进入“cambricon-mlu-driver-xxx-yyy”驱动源码目录

```shell
make clean   # 清除编译残留文件

make -j32    # 编译驱动
```

- 编译前请检查kernel-header路径，mlu驱动选择的路径为 “/lib/modules/${KERNELRELEASE}/build”
- 编译过程中可能会遇到在当前系统里编译无法通过问题， 大部分情况下是因为内核函数发生变化，需要适配为当前内核的调用方式。

- 解决的编译问题，建议使用git formart-patch产生patch交由寒武纪AE合入主线，这样在未来版本里就可以带上修改。

## 1.3 MLU驱动加卸载

驱动加载请使用专用脚本

```shell
sudo ./load_auto   # 此脚本会检查当前系统里mlu设备数量，也会拷贝源码中Firmware.img到指定系统目录。
dmesg | grep "boot ok" #查看内核打印，查询是否有 “card $id boot ok”, 其中$id取值范围和当前系统下识别的MLU设备相关。
```

- 加载过程中可能会遇见加载失败问题。常见问题可以参考《Cambricon-Driver-User-Guide》 “10 注意”章节
- 注意保留加载失败log，发给寒武纪AE进行分析。

使用cnmon检查板卡状态信息，如果使用安装方式，例如：“dpkg -i cambricon-mlu-driver-ubuntu20.04-dkms_4.20.14_amd64.deb” ，可以直接在终端输入“cnmon”命令。

如果使用安装包解压源码本地编译方式，可以在源码目录下，例如：“cambricon-mlu-driver-ubuntu20.04-4.20.14” 寻找cnmon可执行程序。

由于cnmon是可执行程序发布，可能会遇到系统兼容性问题。此时，可以通过驱动proc info节点获取信息，例如：

```shell
cat /proc/driver/cambricon/mlus/0000:00:00.1/information   # 0000:00:00.1 为设备的PCIe BDF号
```

驱动卸载请使用专用脚本

```shell
sudo ./unload_auto

lsmod | grep cam*     # 检查驱动是否卸载成功
```

成功做完一轮加载卸载驱动测试后，建议做加卸载驱动压力测试，可以把上述操作使用脚本循环执行。

如果条件允许，可以把加卸载脚本加入开机启动脚本中，例如：rc.local，通过重启进行驱动加卸载测试，可以同步确认设备在系统中被正确识别的稳定性。

## 1.4 PCIe 连接性基本测试

1 cd ./tools/bw_sample

2 make

3 ./bw_sample --device=all

正常情况能得到Device0到DeviceN（如果是多卡）性能数据，每张卡分别包含6个测试项

第一项：Host to Device Bandwidth，单位GB/s

第二项：Host to Device latency，单位us

第三项：Device to Host Bandwidth，单位GB/s

第四项：Device to Host latency，单位us

第五项：Device to Device Bandwidth，单位GB/s

第六项：Device to Device latency，单位us

如果遇到执行测例卡住、报错误日志，带宽极小等问题，请忙采集程序运行回显信息和dmesg



比如带宽问题：X86 PCIe G3-X16机器，上述程序带宽值在10GB左右。

部分CPU架构可能存在不同Numa node内存对PCIe带宽性能影响很大的已知问题，可以通过使用numactl --membind=xx ./bw_sample（xx是内存numa node id，numactl --hard能查看numa info）

改变不通numanode节点做测试，得到最优性能



\4. ./bw_sample还可以进行size、方向、内存类型、线程数等不同维度的测试(./bw_sample --help可以获得详细帮助信息)

如果只测驱动和硬件能否工作，第3步已能满足。下面列举一些测试命令。

```
./bw_sample --device=0 --memory=pinned --mode=shmoo --dir=bothway --thread=64 --dma_mode=sync
```
测试数据传输性能，指定测试模式为shmoo，该测试模式下会生成大小从16Byte到32MB递增的梯度数据包。测试参数为0号卡，pinned内存模式，双向传输，64线程，DMA模式为同步DMA。测试结果会按梯度输出双向传输的带宽数据矩阵（Host to Device和Device to Host），单位是GB/s。注意输入参数的正确性，若输入不合理的参数，程序会终止并提示相应错误，例如输入不存在的卡序号，或输入线程数小于零等，其他参数请按照--help的要求检查。

```
./bw_sample --device=0 --memory=pageable --mode=shmoo --dir=all
```
与上条命令类似，测试梯度数据包的传输性能。修改内存模式为pageable，测试方向为所有方向，测试结果会输出Host to Device，Device to Host，Device to Device的数据传输带宽和延迟，以及双向传输的数据带宽。

```
./bw_sample --device=all --memory=pageable --mode=small_shmoo --dir=h2d --thread=32 --dma_mode=async variance=1
```
指定测试模式为small_shmoo，该测试模式下会生成大小从4Byte到1KB递增的梯度小尺寸数据包。指定传输方向为Host to Device，DMA模式为异步DMA，选择测试所有卡，测试结果会依次输出所有卡的Host to Device方向传输带宽及延迟，并测试生成多卡传输的Host to Device传输带宽。除此之外，由于指定了variance参数，测试结果会在每个测试组注明多个线程的传输带宽方差。

```
./bw_sample --device=all --mode=small_shmoo --dir=d2h  --thread=16 --dma_mode=sync
```
测试所有卡，d2h方向，同步dma，在16线程下的梯度小尺寸数据包传输带宽数据，测试的数据包大小从4Byte到1KB递增。测试结果会依次输出所有卡的Device to Host方向传输带宽及延迟，并测试生成多卡传输的Device to Host传输带宽。

```
./bw_sample --device=0 --mode=range --start=1024 --end=10240 --increment=1024 --dir=all
```
range模式下自定义数据包大小范围，测试0号卡，所有传输方向下的传输性能，数据包大小从1024Byte到10240Byte以1024Byte递增。测试结果会输出Host to Device，Device to Host，Device to Device，以及双向传输的测试组别数据，每个测试组别会显示梯度增加的数据包的传输带宽。

tools/bw_test_pressure.sh是通过bw_sample测试命令生成的压力测试脚本，可以修改LOOP_NUM参数控制压力测试循环次数，通过./bw_test_pressure.sh指令运行,以进行板卡上的压力测试。若出现权限问题，使用`chmod 777 bw_test_pressure.sh`命令为脚本添加执行权限。
