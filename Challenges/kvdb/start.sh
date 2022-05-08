#!/bin/sh

# workdir
cd /home/ctf

# flag
echo $FLAG > ./flag
export FLAG=""
chown root:root ./flag
chmod 644 ./flag

# checker
while true
do
    ps -ef | grep "kvdb" | grep -v "grep" >/dev/null
    if [ "$?" -eq 1 ]
    then
        chmod 755 ./kvdb
        runuser -u ctf ./run.sh
        chmod 700 ./kvdb
        echo "KVDB service has been started!"
    fi
    sleep 10
done
