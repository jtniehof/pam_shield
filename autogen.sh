#!/bin/sh

export AUTOMAKE=/usr/bin/automake-1.11
export ACLOCAL=/usr/bin/aclocal-1.11

exec autoreconf -fi;
