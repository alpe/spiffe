#!/bin/sh

mkdir -p /var/lib/spiffe/flex/spiffe.io~flex/creds
cp -f /opt/spiffe/flex /var/lib/spiffe/flex/spiffe.io~flex
cp -rf --dereference  /var/lib/spiffe/creds/* /var/lib/spiffe/flex/spiffe.io~flex/
