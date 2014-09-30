# Copyright (c) 2014 Cisco Systems, Inc.

lib_LTLIBRARIES = libfnr.la

include_HEADERS = fnr.h
libfnr_la_SOURCES = fnr.c $(include_HEADERS)
libfnr_la_LDFLAGS = -version-info 1:0:0
libfnr_la_LIBADD = $(LIBSSL)

if DEBUG
    AM_CFLAGS = -g3 -O0
else
    AM_CFLAGS = -O3
endif
