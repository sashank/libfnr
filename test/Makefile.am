# Copyright (c) 2014 Cisco Systems, Inc.

bin_PROGRAMS = ipv4test 
ipv4test_SOURCES = test_ipv4.c
ipv4test_CPPFLAGS = -I../src
ipv4test_LDADD = ../src/libfnr.a

if DEBUG
    AM_CFLAGS = -g3 -O0 -DDEBUG
    AM_CXXFLAGS = -g3 -O0 -DDEBUG
else
    AM_CFLAGS = -O2
    AM_CXXFLAGS = -O2
endif
