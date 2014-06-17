noinst_LIBRARIES=libfnr.a
libfnr_a_SOURCES=fnr.c fnr.h

libfnr_a_LIBADD = $(LIBSSL)

#bin_PROGRAMS = fnr
#fnr_SOURCES = main.c
#fnr_LDADD = libfnr.a

if DEBUG
    AM_CFLAGS = -g3 -O0
    AM_CXXFLAGS = -g3 -O0
else
    AM_CFLAGS = -O3
    AM_CXXFLAGS = -O3
endif
