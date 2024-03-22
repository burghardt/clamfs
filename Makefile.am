SUBDIRS = src doc

EXTRA_DIST = bootstrap m4 version.h

BUILT_SOURCES = version.h

version.h:
if DOT_GIT
	echo "#define PACKAGE_VERSION_GIT_DESCRIBE \"`git describe --always --dirty --broken`\"" > version.h
else
	echo '#define PACKAGE_VERSION_GIT_DESCRIBE "unknown"' > version.h
endif

doxygen:
	make -C doc doxygen
