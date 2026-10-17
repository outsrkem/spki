#!/bin/sh

if [ -z "$1" ];then
  set -- /usr/local/bin/spki -c /etc/spki/spki.yaml
fi

exec "$@"
