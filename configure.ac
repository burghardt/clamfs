AC_INIT([ClamFS], [1.2.0], [krzysztof@burghardt.pl], [clamfs])
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_SRCDIR(src/clamfs.cxx)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE
AM_CONDITIONAL([DOT_GIT], [test -d .git])

# Checks for programs
AC_PROG_CXX
AC_PROG_CC

# Set language to C++
AC_LANG_CPLUSPLUS

# Checks for header files
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h string.h unistd.h stdlib.h malloc.h])

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
AC_CHECK_FUNCS([fchdir fdatasync fork ftruncate fstatat utimensat posix_fallocate copy_file_range lchown memset mkdir mkfifo rmdir setxattr strdup strerror utime mallinfo mallinfo2])

# Check for BSD 4.4 / RFC2292 style fd passing
AC_C_FDPASSING

# Set initial CPPFLAGS and LDFLAGS
CPPFLAGS="$CPPFLAGS -Wall -Werror -Wextra -Wdate-time"
CPPFLAGS="$CPPFLAGS -Wformat -Wformat-security -D_FORTIFY_SOURCE=2"
CPPFLAGS="$CPPFLAGS -Wcast-align -Wcast-qual -Wchar-subscripts"
CPPFLAGS="$CPPFLAGS -Wformat-nonliteral -Wpointer-arith -Wredundant-decls"
CPPFLAGS="$CPPFLAGS -Wreturn-type -Wshadow -Wswitch -Wunused-parameter -Wwrite-strings"
CPPFLAGS="$CPPFLAGS -fstack-protector-strong -fPIC -fPIE"
LDFLAGS="$LDFLAGS -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--as-needed -Wl,-Bsymbolic-functions -Wl,--fatal-warnings"

# Checks for boost
AX_BOOST_BASE(1.33)
CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
LDFLAGS="$LDFLAGS $BOOST_LDFLAGS"

# Check for libfuse3
PKG_CHECK_MODULES([FUSE3],[fuse3 >= 3],
    [CPPFLAGS="$CPPFLAGS $FUSE3_CFLAGS -pthread -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=31"
     LIBS="$LIBS $FUSE3_LIBS"])
PKG_CHECK_MODULES([FUSE38],[fuse3 >= 3.8],AC_DEFINE([HAVE_FUSE_LSEEK],[1],[Define to 1 if you have the lseek() support in FUSE library.]),
    AC_MSG_WARN([disabling lseek() support as building with FUSE version < 3.8.0]))

# Check for libulockmgr
AC_CHECK_HEADER(ulockmgr.h,AC_DEFINE([HAVE_LIBULOCKMGR],[1],[Define to 1 if you have the `ulockmgr` library.]))
AC_CHECK_LIB(ulockmgr,ulockmgr_op,LIBS="$LIBS -lulockmgr")

# Check for librlog
CPPFLAGS="$CPPFLAGS -DRLOG_COMPONENT=clamfs"
AC_CHECK_HEADER(rlog/rlog.h,,AC_MSG_ERROR([rlog/rlog.h not found!]))
AC_CHECK_LIB(rlog,RLogVersion,LIBS="$LIBS -lrlog",AC_MSG_ERROR([librlog not found!]))

# Check for libpoco
AC_CHECK_HEADER(Poco/Exception.h,,AC_MSG_ERROR([Poco/Exception.h]))
AC_CHECK_HEADER(Poco/ExpireLRUCache.h,,AC_MSG_ERROR([Poco/ExpireLRUCache.h not found!]))
AC_CHECK_HEADER(Poco/Net/MailMessage.h,,AC_MSG_ERROR([Poco/Net/MailMessage.h]))
AC_CHECK_HEADER(Poco/Net/MailRecipient.h,,AC_MSG_ERROR([Poco/Net/MailRecipient.h]))
AC_CHECK_HEADER(Poco/Net/SMTPClientSession.h,,AC_MSG_ERROR([Poco/Net/SMTPClientSession.h]))
AC_CHECK_HEADER(Poco/SAX/SAXParser.h,,AC_MSG_ERROR([Poco/SAX/SAXParser.h]))
AC_CHECK_HEADER(Poco/SAX/ContentHandler.h,,AC_MSG_ERROR([Poco/SAX/ContentHandler.h]))
AC_CHECK_HEADER(Poco/SAX/LexicalHandler.h,,AC_MSG_ERROR([Poco/SAX/LexicalHandler.h]))
AC_CHECK_HEADER(Poco/SAX/Attributes.h,,AC_MSG_ERROR([Poco/SAX/Attributes.h]))
AC_CHECK_HEADER(Poco/SAX/Locator.h,,AC_MSG_ERROR([Poco/SAX/Locator.h]))

# There is no portable way to check for C++ symbol with AC_CHECK_LIB().
# Mangling C++ symbols is not portable. Hacks like using main() or _start()
# are neither portable enough. Calling main() is forbidden in C++.
# Symbol _start() is non-standard and does not exists on mips(64)el.

#AC_CHECK_LIB(PocoFoundation,_start,LIBS="$LIBS -lPocoFoundation",AC_MSG_ERROR([libPocoFoundation not found!]))
#AC_CHECK_LIB(PocoNet,_start,LIBS="$LIBS -lPocoNet",AC_MSG_ERROR([libPocoNet not found!]))
#AC_CHECK_LIB(PocoXML,_start,LIBS="$LIBS -lPocoXML",AC_MSG_ERROR([libPocoXML not found!]))

LIBS="$LIBS -lPocoFoundation -lPocoNet -lPocoXML"

# Use option --enable-gcc-debug to enable GCC debug code.
AC_ARG_ENABLE(gcc-debug,
AC_HELP_STRING([--enable-gcc-debug],
        [enable GCC DEBUG code]),
        [enable_gcc_debug=yes],
        [enable_gcc_debug=no])
if test "$enable_gcc_debug" = "yes" && (test "$GXX" = "yes"); then
 CPPFLAGS="$CPPFLAGS -O0 -ggdb"
 AC_MSG_RESULT([Enabling GCC debug...])
else
 CPPFLAGS="$CPPFLAGS -O2 -DNDEBUG"
fi

# Use option --enable-clang-flags to enable CLANG flags.
AC_ARG_ENABLE(clang-flags,
AC_HELP_STRING([--enable-clang-flags],
        [enable enable CLANG flags]),
        [enable_clang_flags=yes],
        [enable_clang_flags=no])
if test "$enable_clang_flags" = "yes" && (test "$GXX" = "yes"); then
 CPPFLAGS="$CPPFLAGS -Wfour-char-constants -Wpointer-arith -Wwrite-strings -Wcast-align"
 CPPFLAGS="$CPPFLAGS -Wconversion -Wfloat-equal -Wformat=2 -Wimplicit-atomic-properties"
 CPPFLAGS="$CPPFLAGS -Wmissing-declarations"
 CPPFLAGS="$CPPFLAGS -Woverlength-strings -Wshadow"
 CPPFLAGS="$CPPFLAGS -Wstrict-selector-match -Wundeclared-selector"
 CPPFLAGS="$CPPFLAGS -Wunreachable-code -Wthread-safety"
 AC_MSG_RESULT([Enabling CLANG flags...])
fi

# Use option --enable-dmalloc-debug to enable dmalloc debug code.
AC_ARG_ENABLE(dmalloc-debug,
AC_HELP_STRING([--enable-dmalloc-debug],
        [enable dmalloc debug code]),
        [enable_dmalloc_debug=yes],
        [enable_dmalloc_debug=no])
if test "$enable_dmalloc_debug" = "yes" && (test "$GXX" = "yes"); then
 AC_CHECK_HEADER(dmalloc.h,CPPFLAGS="$CPPFLAGS -DDMALLOC",AC_MSG_ERROR([dmalloc.h not found!]))
 AC_CHECK_LIB(dmallocthcxx,dmalloc_shutdown,LIBS="$LIBS -ldmallocthcxx",AC_MSG_ERROR([libdmallocthcxx not found!]))
 AC_MSG_RESULT([Enabling dmalloc debug...])
fi

# Use option --gprof to enable gprof support
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
