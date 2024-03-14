# 一、概要

本文档主要介绍自主适配工具集的编译、使用等方面。

# 二、编译

基于Makefile是实现一键编译。

```
make 编译
make clean 清理
```

# 三、工具介绍

自主适配工具集支持bw_sample、p2p_sample、pcie_copy、p2p_copy、d2d_copy、complex等六种测试工具。其中前两者为性能测试工具，其他为功能测试工具。

## 3.1、性能测试工具

性能测试工具主要关注各种条件组合（不同线程数、不同大小数据包、不同对齐方式、不同内存类型）情况下的带宽表现。

### 3.1.1、bw_sample

测试主机与设备之间的内存拷贝带宽性能。

```shell
./bw_sample --help
Usage:  bandwidthTest [OPTION]...

Options:
--help			Display this help menu
--device=[deviceno]	default:0
  0,1,2,...,n		Specify any particular device to be used
--memory=[MEMMODE]	default:pinned
  pageable		pageable memory
  pinned		non-pageable system memory
--mode=[MODE]		default:quick
  quick			performs a quick measurement
  range			measures a user-specified range of values
  shmoo			performs an intense shmoo of a large range of values
  small_shmoo		performs an intense shmoo of a small range of values
--dir=[DIRECTION]	default:all
  h2d			Measure host to device transfers
  d2h			Measure device to host transfers
  d2d			Measure device to device transfers
  memset		Measure device memset transfers
  bothway		Measure host to device and device to host transfers
  d2d_2d		Measure device to device 2D transfers
  d2d_3d		Measure device to device 3D transfers
  all			Measure host to device and device to host transfers
--thread=[THREAD_NUM]	default:1 max:1024
--dma_mode=[DMAMODE]	default:async
  sync			use sync dma to get bandwidth
  async			use async dma to get bandwidth
  async_no_batch	use async dma no batch to get bandwidth
--repeat_num=[NUM]	test repeat num default:1 max:1000
--th_repeat_num=[NUM]	thread repeat num default:100
--variance=[MODE]	default:no_need
  no_need		no need variance
  thread_mode		multithread bandwidth variance
  repeat_mode		multirepeat bandwidth variance
--sta_range=[0-100]	stability score limit percent range
--latency_mode=[MODE]	async dma latency mode default:hw_latency
  hw_latency		get async copy 4B data latency hardware time
  sw_latency		get async copy 4B data latency software time
  api_latency		get async copy api latency software time
--numa_mode=[MODE]	numa mode default:disable
  disable		disable numa node bind
  enable		enable cpunodebind and membind
  cpu			enable cpunodebind
  mem			enable membind
Range mode options
--start=[SIZE]		Starting transfer size in bytes
--end=[SIZE]		Ending transfer size in bytes
--increment=[SIZE]	Increment size in bytes
Multi Dim options
--width_shift==[N]	width left shift setting
  0        		No left shift. Default.
  1/2/...32		Let it left shift N each time
--init_width==[N]	width init setting
  1/2/..Edge		The width init value is N, default 0x10.2D_Edge(0x100000) 3D_Edge(0x100000)
--init_depth==[N]	depth init setting
  1/2/.....n		The depth init value is N and keep it during test. Default 4.
--memset_width==[N]	memset handle width setting
  8/16/32		The memset handle width init for MemsetD8/16/32 Default 8.
--noaligned=[flag]	flag=1 enable noaligned_test flag=0 disable noaligned

Example:
./bw_sample --device=0 --mode=range --start=1024 --end=10240 --increment=1024 --dir=all
./bw_sample --device=0 --memory=pinned --mode=shmoo --dir=bothway --thread=64 --dma_mode=sync
./bw_sample --device=0 --memory=pinned --mode=shmoo --dir=h2d --thread=4 --dma_mode=sync --repeat_num=10 --th_repeat_num=100 --variance=repeat_mode --sta_range=10
```

### 3.1.2、p2p_sample

测试不同设备之间的内存拷贝带宽性能。

```shell
./p2p_sample --help
Usage:  bandwidthTest [OPTION]...

Options:
--help			Display this help menu
--src_dev=[deviceno]	default:all
--dst_dev=[deviceno]	default:all
  all			compute cumulative bandwidth on all the devices
  0,1,2,...,n		Specify any particular device to be used
--mode=[MODE]		default:quick
  quick			performs a quick measurement
  range			measures a user-specified range of values
  shmoo			performs an intense shmoo of a large range of values
  small_shmoo		performs an intense shmoo of a small range of values
--dir=[DIRECTION]	default:oneway
  oneway		Measure unidirectional transfers
  bothway		Measure directional transfers
--thread=[THREAD_NUM]	default:1 max:1024
--dma_mode=[DMAMODE]	default:async
  sync			use sync dma to get bandwidth
  async			use async dma to get bandwidth
  async_no_batch	use async dma no batch to get bandwidth
--repeat_num=[NUM]	test repeat num default:1 max:1000
--th_repeat_num=[NUM]	thread repeat num default:100
--variance=[MODE]	default:no_need
  no_need		no need variance
  thread_mode		multithread bandwidth variance
  repeat_mode		multirepeat bandwidth variance
--sta_range=[0-100]	stability score limit percent range
--latency_mode=[MODE]	async dma latency mode default:hw_latency
  hw_latency		get async copy 4B data latency hardware time
  sw_latency		get async copy 4B data latency software time
  api_latency		get async copy api latency software time
Range mode options
--start=[SIZE]		Starting transfer size in bytes
--end=[SIZE]		Ending transfer size in bytes
--increment=[SIZE]	Increment size in bytes

Example:
./p2p_sample --src_dev=0 --dst_dev=1 --mode=range --start=1024 --end=10240 --increment=1024 --dir=oneway
./p2p_sample --src_dev=0 --dst_dev=1 --mode=shmoo --dir=bothway --thread=64 --dma_mode=sync
./p2pBandwidthLatencyTest --src_dev=0 --dst_dev=1 --mode=shmoo --dir=oneway --thread=4 --dma_mode=sync --repeat_num=10 --th_repeat_num=100 --variance=repeat_mode --sta_range=10

```

## 3.2、功能测试工具

功能测试工具主要关注各种条件组合（不同线程数、不同大小数据包、不同对齐方式、不同内存类型）情况下的拷贝的正确性，尤其complex工具属于多数据流并行的压力测试。

### 3.2.1、pcie_copy

测试卡与主机之间的数据拷贝功能。
```shell
./pcie_copy --help
Usage:  pcie_copy Test [OPTION]...

Options:
--help			Display this help menu
--device=[deviceno]	default:0
  0,1,2,...,n		Specify any particular device to be used
--memory=[MEMMODE]	default:pinned
  pageable		pageable memory
  pinned		non-pageable system memory
--thread=[THREAD_NUM]	default:1
--repeat=[REPEAT_NUM]	default:1
--noaligned=[FLAG]	default:FLAG=1 enable noaligned_test FLAG=0 disable noaligned
--dma_mode=[DMAMODE]	default:all
  sync			use sync dma to copy
  async			use async dma to copy
  all			use sync and async dma to copy
--mode=[MODE]		default:check
  check			output result only
  detail		output detail
  checknon		do not check
  checkatlast		check at the last loop only

Example:
./pcie_copy --device=0,1 --thread=10 --repeat=10 --dma_mode=sync
./pcie_copy --device=0 --memory=pinned --thread=10 --repeat=10 --noaligned=0
./pcie_copy --device=0 --memory=pageable --thread=10 --repeat=10 --mode=detail
```
### 3.2.2、p2p_copy

测试不同卡之间（须为多卡环境）的数据拷贝功能。
```shell
./p2p_copy  --help
Usage:  p2p_copy Test [OPTION]...

Options:
--help			Display this help menu
--src_dev=[deviceno]	default:all
--dst_dev=[deviceno]	default:all
  all			compute cumulative bandwidth on all the devices
  0,1,2,...,n		Specify any particular device to be used
--thread=[THREAD_NUM]	default:1
--repeat=[REPEAT_NUM]	default:1
--dma_mode=[DMAMODE]	default:all
  sync			use sync dma to copy
  async			use async dma to copy
  all			use sync and async dma to copy
--mode=[MODE]		default:check
  check			output result only
  detail		output detail
  checknon		do not check
  checkatlast		check at the last loop only

Example:
./p2p_copy --thread=10 --repeat=10 --mode=detail
./p2p_copy --thread=10 --repeat=10 --dma_mode=sync
./p2p_copy --src_dev=0 --dst_dev=1 --thread=10 --repeat=10
```
### 3.2.3、d2d_copy

测试单卡每部不同内存之间的数据拷贝功能。
```shell
./d2d_copy --help
Usage:  d2d_copy Test [OPTION]...

Options:
--help			Display this help menu
--device=[deviceno]	default:0
  0,1,2,...,n		Specify any particular device to be used
--thread=[THREAD_NUM]	default:1
--repeat=[REPEAT_NUM]	default:1
--dma_mode=[DMAMODE]	default:all
  sync			use sync dma to copy
  async			use async dma to copy
  all			use sync and async dma to copy
--mode=[MODE]		default:check
  check			output result only
  detail		output detail
  checknon		do not check
  checkatlast		check at the last loop only

Example:
./d2d_copy --device=0,1,2 --thread=10 --repeat=10
./d2d_copy --device=0 --thread=10 --repeat=10 --dma_mode=sync
./d2d_copy --device=0 --thread=10 --repeat=10 --mode=detail
```
### 3.3.3、complex

该工具实现压力测试，即通过并行调用前面提到各个工具，实现多数据流并发。
```
./complex --help
Help Info:
-h|--help ................ Show help infornation.
-v|--version ............. Show version of test.
-t|--timecnt N ........... Set how long test running, default 5 minutes.
-l|--list ................ List all these cases it support.
-f|--filter "a;b" ........ Filter which cases to run and -l can get list. default test all.
-e|--erraction mode ...... Config erraction who has exitall or stopself, default exitall.
   --plugincfg path ...... Set test plugin config file, default 'complex_config/default.conf'.
```
