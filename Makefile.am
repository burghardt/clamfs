SUBDIRS = src doc

EXTRA_DIST = bootstrap \
             ax_boost_base.m4 \
             fdpassing.m4 \
             version.h

BUILT_SOURCES = version.h

acinclude.m4: ax_boost_base.m4 fdpassing.m4
	cat ax_boost_base.m4 fdpassing.m4 > acinclude.m4

version.h:
if DOT_GIT
	echo "#define PACKAGE_VERSION_GIT_DESCRIBE \"`git describe --always --dirty --broken`\"" > version.h
else
	echo '#define PACKAGE_VERSION_GIT_DESCRIBE "unknown"' > version.h
endif

doxygen:
	make -C doc doxygen
