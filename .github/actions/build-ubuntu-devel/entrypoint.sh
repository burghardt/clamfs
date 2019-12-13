#!/bin/sh -lxe

sh bootstrap
sh configure || { tail -n 300 config.log; false; }
make clean
make -j
