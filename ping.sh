#!/usr/bin/sh

#sends 30 ping packets to ip address passed in as first argument.

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` ip_address"
  exit $E_BADARGS
fi

ping -c 30 $@

