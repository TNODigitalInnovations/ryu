#!/bin/bash

BASEDIR=`dirname $0`

PYTHONPATH=$BASEDIR $BASEDIR/bin/ryu-manager --verbose --observe-links $BASEDIR/ryu/app/AnyMatchSwitch.py
