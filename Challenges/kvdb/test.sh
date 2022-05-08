#!/bin/sh
sudo docker build --tag kvdb .
sudo docker run -it --rm -p 9999:9999 -e FLAG="minil{test_flag}" kvdb
