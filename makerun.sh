#!/usr/bin/env bash

make

cp --verbose /home/ashur/knot-dns/resolver/modules/sink/sink.so /usr/local/lib/kdns_modules/

kresd --config=/usr/local/etc/kresd/config.personal --verbose --addr=192.168.10.129