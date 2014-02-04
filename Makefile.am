AUTOMAKE_OPTIONS        = foreign
ACLOCAL_AMFLAGS         = -I autotools
AM_MAKEFLAGS            = -s

pkglib_LTLIBRARIES	= secureserv.la
secureserv_la_SOURCES	= Helpers.c SecureServ.c scan.c OnJoinBot.c SecureServ_help.c update.c
noinst_HEADERS		= SecureServ.h 

secureserv_la_LDFLAGS	= -module -avoid-version

EXTRA_DIST		= autotools/ccdv.c autotools/shtool RELNOTES

dist_doc_DATA		= README.SecureServ README.SecureServ.html
dist_data_DATA		= viri.dat


include $(top_srcdir)/autotools/rules.mk
