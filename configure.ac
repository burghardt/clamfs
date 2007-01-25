AC_INIT([ClamFS], [0.0.1], [krzysztof@burghardt.pl], [clamfs])
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_SRCDIR(src/clamfs.cxx)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE

# Checks for programs
AC_PROG_CXX

# Set language to C++
AC_LANG_CPLUSPLUS

# Check for fork, setxattr and fdatasync functions
AC_CHECK_FUNCS([fork setxattr fdatasync])

# Checks for libfuse
CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=25 -DRLOG_COMPONENT=clamfs"
AC_CHECK_HEADER(fuse.h,,AC_MSG_ERROR([fuse.h not found!]))
AC_CHECK_LIB(fuse,fuse_main,LIBS="$LIBS -lfuse",AC_MSG_ERROR([libfuse not found!]))

# Check for librlog
AC_CHECK_HEADER(rlog/rlog.h,,AC_MSG_ERROR([rlog/rlog.h not found!]))
AC_CHECK_LIB(rlog,main,LIBS="$LIBS -lrlog",AC_MSG_ERROR([librlog not found!]))

# Check for libpoco
AC_CHECK_HEADER(Poco/ExpireLRUCache.h,,AC_MSG_ERROR([Poco/ExpireLRUCache.h not found!]))
AC_CHECK_LIB(PocoFoundation,main,LIBS="$LIBS -lPocoFoundation",AC_MSG_ERROR([libpoco not found!]))

# Check for libccgnu2 (via ccgnu2-config)
AC_MSG_CHECKING(for libccgnu2 via ccgnu2-config)
if test -x "`which ccgnu2-config 2>/dev/null`"; then
    CPPFLAGS="$CPPFLAGS `ccgnu2-config --flags`"
    CPPFLAGS="$CPPFLAGS `ccgnu2-config --includes`"
    LIBS="$LIBS `ccgnu2-config --stdlibs`"
    AC_MSG_RESULT(yes)
else
    AC_MSG_ERROR([libccgnu2 not found!])
fi

dnl Use option --enable-gcc-debug to enable GCC debug code. 
AC_ARG_ENABLE(gcc-debug,
AC_HELP_STRING([--enable-gcc-debug],
        [enable GCC DEBUG code]),
        [enable_gcc_debug=yes],
        [enable_gcc_debug=no])
if test "$enable_gcc_debug" = "yes" && (test "$GXX" = "yes"); then
 CPPFLAGS="$CPPFLAGS -Wall -O0 -ggdb"
 AC_MSG_RESULT([Enabling GCC debug...])
else
 CPPFLAGS="$CPPFLAGS -Wall -O2 -DNDEBUG"
fi

dnl Use option --gprof to enable gprof support
AC_ARG_ENABLE(gprof,
AC_HELP_STRING([--enable-gprof],
        [enable gprof support]),
        [enable_gprof=yes],
        [enable_gprof=no])
if test "$enable_gprof" = "yes" && (test "$GXX" = "yes"); then
 CPPFLAGS="$CPPFLAGS -pg"
 AC_MSG_RESULT([Enabling gprof...])
fi

AC_CONFIG_FILES([Makefile
 src/Makefile
 doc/Makefile
 debian/Makefile
 ])
AC_OUTPUT
