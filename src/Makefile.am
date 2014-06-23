# Copyright (c) 2014 Cisco Systems, Inc.

noinst_LIBRARIES=libfnr.a
libfnr_a_SOURCES=fnr.c fnr.h

libfnr_a_LIBADD = $(LIBSSL)

#bin_PROGRAMS = fnr
#fnr_SOURCES = main.c
#fnr_LDADD = libfnr.a

if DEBUG
    AM_CFLAGS = -g3 -O0
else
    AM_CFLAGS = -O3
endif
