#!/bin/sh
# Add your startup script
echo $FLAG > /app/flag && export FLAG=''
# DO NOT DELETE
socat tcp-l:9999,reuseaddr,fork,su=user exec:/app/bugged_interpreter