AC_INIT([ClamFS], [1.0.1], [krzysztof@burghardt.pl], [clamfs])
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_SRCDIR(src/clamfs.cxx)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE

# Checks for programs
AC_PROG_CXX
AC_PROG_CC

# Set language to C++
AC_LANG_CPLUSPLUS

# Checks for header files
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

# Check for functions
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_UTIME_NULL
AC_CHECK_FUNCS([fchdir fdatasync fork ftruncate lchown memset mkdir mkfifo rmdir setxattr strdup strerror utime])

# Checks for boost
AX_BOOST_BASE(1.33)
CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
LDFLAGS="$LDFLAGS $BOOST_LDFLAGS"

# Checks for libfuse
CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=25 -DRLOG_COMPONENT=clamfs"
AC_CHECK_HEADER(fuse.h,,AC_MSG_ERROR([fuse.h not found!]))
AC_CHECK_LIB(fuse,fuse_main,LIBS="$LIBS -lfuse",AC_MSG_ERROR([libfuse not found!]))

# Check for librlog
AC_CHECK_HEADER(rlog/rlog.h,,AC_MSG_ERROR([rlog/rlog.h not found!]))
AC_CHECK_LIB(rlog,main,LIBS="$LIBS -lrlog",AC_MSG_ERROR([librlog not found!]))

# Check for libpoco
AC_CHECK_HEADER(Poco/ExpireLRUCache.h,,AC_MSG_ERROR([Poco/ExpireLRUCache.h not found!]))
AC_CHECK_HEADER(Poco/Net/MailMessage.h,,AC_MSG_ERROR([Poco/Net/MailMessage.h]))
AC_CHECK_HEADER(Poco/Net/MailRecipient.h,,AC_MSG_ERROR([Poco/Net/MailRecipient.h]))
AC_CHECK_HEADER(Poco/Net/SMTPClientSession.h,,AC_MSG_ERROR([Poco/Net/SMTPClientSession.h]))
AC_CHECK_HEADER(Poco/Net/StringPartSource.h,,AC_MSG_ERROR([Poco/Net/StringPartSource.h]))
AC_CHECK_LIB(PocoFoundation,main,LIBS="$LIBS -lPocoFoundation",AC_MSG_ERROR([libPocoFoundation not found!]))
AC_CHECK_LIB(PocoFoundation,main,LIBS="$LIBS -lPocoNet",AC_MSG_ERROR([libPocoNet not found!]))

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

dnl Use option --enable-dmalloc-debug to enable dmalloc debug code. 
AC_ARG_ENABLE(dmalloc-debug,
AC_HELP_STRING([--enable-dmalloc-debug],
        [enable dmalloc debug code]),
        [enable_dmalloc_debug=yes],
        [enable_dmalloc_debug=no])
if test "$enable_dmalloc_debug" = "yes" && (test "$GXX" = "yes"); then
 AC_CHECK_HEADER(dmalloc.h,CPPFLAGS="$CPPFLAGS -DDMALLOC",AC_MSG_ERROR([dmalloc.h not found!]))
 AC_CHECK_LIB(dmallocthcxx,main,LIBS="$LIBS -ldmallocthcxx",AC_MSG_ERROR([libdmallocthcxx not found!]))
 AC_MSG_RESULT([Enabling dmalloc debug...])
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
 doc/Doxyfile
 doc/svg/Makefile
 ])
AC_OUTPUT
