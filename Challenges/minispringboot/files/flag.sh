#!/bin/bash

echo $FLAG > /flag
export FLAG=flag_not_here
FLAG=flag_not_here
rm -f /flag.sh
