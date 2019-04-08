#!/bin/sh

uds=$1

./mdish.manifest.sgx -v -Z /srv/root.crt /srv/proc.crt /srv/proc.key $1
