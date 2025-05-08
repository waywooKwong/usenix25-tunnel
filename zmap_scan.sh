#!/bin/bash

# 使用 ZMap 扫描是否主机可达（这里选 ICMP Echo 或 TCP 80 探测）
# 注意：你可换成任何你认为“代表主机活跃”的端口

zmap -p 80 -B 10M -n 100000 --output-file=targets.txt
