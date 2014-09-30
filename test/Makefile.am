# Copyright (c) 2014 Cisco Systems, Inc.

bin_PROGRAMS = ipv4test 
ipv4test_SOURCES = test_ipv4.c
ipv4test_CPPFLAGS = -I$(top_srcdir)/src
ipv4test_LDADD = $(top_builddir)/src/.libs/libfnr.a
ipv4test_DEPENCENCIES = $(ipv4test_LDADD)

EXTRA_DIST = generate_ipv4.py

if DEBUG
    AM_CFLAGS = -g3 -O0 -DDEBUG
    AM_CXXFLAGS = -g3 -O0 -DDEBUG
else
    AM_CFLAGS = -O2
    AM_CXXFLAGS = -O2
endif
