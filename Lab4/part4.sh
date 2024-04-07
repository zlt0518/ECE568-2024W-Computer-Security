#!/bin/bash

./bin/rndc -c etc/rndc.conf querylog

# start part4_starter.py service
python2 part4_starter.py --ip 127.0.0.1 --port 12222 --query_port 12221

# cache support
./bin/rndc -c etc/rndc.conf dumpdb -cache
less /u/c/linyiha1/Documents/winter/ece568/lab4/named_dump.db
