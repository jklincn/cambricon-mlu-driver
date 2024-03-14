
# !/usr/bin/bash

# This script use bw_sample tool to generate stress test scripts, modify LOOP_NUM to control the number of cycles.
cd bw_sample
LOOP_NUM=100

if [ ! -f "bw_sample" ]; then
    make
fi

for((i=0; i<$LOOP_NUM; i++))
do
    ./bw_sample --device=0 --memory=pinned --mode=shmoo --dir=bothway --thread=64 --dma_mode=sync
    ./bw_sample --device=0 --memory=pageable --mode=shmoo
    ./bw_sample --device=all --memory=pageable --mode=small_shmoo --dir=h2d --thread=32 --dma_mode=async variance=1
    ./bw_sample --device=all --mode=small_shmoo --dir=d2h  --thread=16 --dma_mode=sync
    ./bw_sample --device=0 --mode=range --start=1024 --end=10240 --increment=1024 --dir=all
done
