#!/bin/sh -lxe

sh bootstrap
sh configure --disable-dependency-tracking
make clean
make -j
