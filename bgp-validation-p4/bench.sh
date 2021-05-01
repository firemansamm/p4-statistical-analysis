#!/bin/bash

bold=`tput bold`
normal=`tput sgr0`

#while true
#do
    for ((i=1;i<=50;i++));
    do
        node=${1:-h1-$i}
        out=`curl -s -S -n 18.0.1.1 -o /dev/null -w "%{time_total},%{size_download},%{speed_download}\n" >> stats.log`
        #date=`date`
        #echo $date -- $bold$out$normal
        #echo $out >> curl-stats.txt
        #sleep 2
    done
#done