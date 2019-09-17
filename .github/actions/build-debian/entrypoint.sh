#!/bin/sh -lxe

sh bootstrtap
sh configure
make clean
make -j
