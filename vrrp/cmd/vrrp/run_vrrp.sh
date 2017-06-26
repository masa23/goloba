#!/bin/sh
exec ./vrrp \
  -local_addr=192.168.122.247 -remote_addr=192.168.122.141 \
  -vip=192.168.122.2/32 -vip_dev eth0
