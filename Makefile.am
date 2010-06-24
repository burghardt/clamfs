SUBDIRS = src doc

EXTRA_DIST = bootstrap \
             ax_boost_base.m4 \
             version.h

acinclude.m4: ax_boost_base.m4
	cat ax_boost_base.m4 > acinclude.m4

if DOT_SVN
version.h: .svn/entries
else
version.h:
endif
	echo \#define PACKAGE_VERSION_SVN_REV \"SVN-r`svnversion`\" > version.h

all: config.h version.h
	$(MAKE) $(AM_MAKEFLAGS) all-recursive
