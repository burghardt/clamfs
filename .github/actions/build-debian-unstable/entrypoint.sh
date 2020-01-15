#!/bin/sh -lxe

sh bootstrap
sh configure || { tail -n 500 config.log; false; }
make clean
make -j
