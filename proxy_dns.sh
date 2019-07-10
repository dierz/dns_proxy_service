#!/bin/bash

case "$1" in 
start)
   /root/main
   ;;
stop)
   kill -15 `cat /var/run/main.pid`
   rm /var/run/main.pid
   ;;
restart)
   $0 stop
   $0 start
   ;;
status)
   if [ -e /var/run/main.pid ]; then
      echo proxy-dns is running, pid=`cat /var/run/main.pid`
   else
      echo proxy-dns is NOT running
      exit 1
   fi
   ;;
*)
   echo "Usage: $0 {start|stop|status|restart}"
esac

exit 0 