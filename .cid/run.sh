#!/bin/bash
workspace=$(cd `dirname $0`/..; pwd)
cd $workspace

docker-compose -f .cid/docker-compose.yaml up --pull always  -d
