#!/bin/bash

cd impacket
./smbserver.py -debug a tmp/
cd -
