# Gdr使用说明

## Gdr实现原理

Gdrcopy功能实现在host用户态，直接访问device内存的功能。
工作原理：通过两次地址映射把device VA映射到host侧VA；第一次映射remap device VA to BAR VA，通过BAR VA可得到BAR PA，第二次映射，map BAR PA到host用户态VA。
Gdrcopy的内存映射实现依赖cnhost_drv驱动，因此必须要保证cnhost_drv驱动先加载。

## 目录说明

```bash
gdrdrv/
├── gdr
│   ├── gdrlib //库文件，编译后生成libgdrapi.so
│   │   ├── config_arch
│   │   ├── gdrapi.c
│   │   ├── gdrapi.h
│   │   ├── gdrconfig.h
│   │   ├── gdrdrv.h
│   │   ├── Makefile
│   │   ├── memcpy_avx.c
│   │   ├── memcpy_sse41.c
│   │   └── memcpy_sse.c
│   └── sample //测例，编译后生成两个可执行测例copybw和copylat
│       ├── copybw.c //测试带宽测例
│       ├── copylat.c //测试latency测例
│       └── Makefile
├── gdrdrv.c //gdr驱动，随cambricon-drv.ko一起编译生成cambricon-gdrdrv.ko
├── gdrdrv.h
└── README.md
```

## Gdrlib接口说明

接口定义说明，可参考gdrapi.h和测例copybw.c两个文件。

## 运行Gdr 测试例

Gdr sample依赖cntoolkit，请按照cntoolkit手册正确安装cntoolkit并设置好环境变量。

按照以下步骤运行测试例：

1. 编译加载驱动cambricon-gdrdrv.ko
2. 编译libgdrapi.so库文件
3. 编译sample中的测例
4. 使用如下命令添加gdrapi库文件到环境变量
export LD_LIBRARY_PATH="../gdrlib/":${LD_LIBRARY_PATH}
5. 执行测例

