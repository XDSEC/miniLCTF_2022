#!/bin/sh
# Add your startup script
echo $FLAG > ./flag && export FLAG=''
# DO NOT DELETE
python next-server.py