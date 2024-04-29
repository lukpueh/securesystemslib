#!/usr/bin/env bash

$pid=(pgrep -f vault)
kill $pid

# make sure to exit with 0
while kill -0 $pid
do
    sleep 1
done
exit 0
