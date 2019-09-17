#!/bin/sh -lxe

sh bootstrap
sh configure
make clean
make -j
