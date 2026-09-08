#!/bin/sh
set -e
/usr/sbin/rsyslogd
/usr/sbin/sshd -D
