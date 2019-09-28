/*!\file rlog.hxx

   \brief RLog logging routines (header file)

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2007-2019 Krzysztof Burghardt

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef CLAMFS_RLOG_HXX
#define CLAMFS_RLOG_HXX

#include "config.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>
#include <rlog/RLogChannel.h>
#include <rlog/SyslogNode.h>
#include <rlog/StdioNode.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "config.hxx"
#include "utils.hxx"

namespace clamfs {

using namespace std;
/*!\namespace rlog
   \brief RLog logging library namespace
*/
using namespace rlog;

/*!\def DEBUG
   \brief Debugging macro
   \param format printf()-like formated output string
   \param args format string arguments

   This macro depending on current (run-time) configuration
   sends or omits debugging messsages to RLog. If ClamFS is
   compiled with -DNDEBUG (normaly) it check if verbose has
   been set in configuration options. If NDEBUG was not defined
   (sources configured with --enable-gcc-debug) it always sends
   messages (regardless of configuration file settings).
*/
#ifndef NDEBUG
#define DEBUG(format, args...) \
    rLog(Debug, format, ## args);
#else
#define DEBUG(format, args...) do { \
    if ((config["verbose"] != NULL) && \
        (strncmp(config["verbose"], "yes", 3) == 0)) { \
        rLog(Debug, format, ## args); \
    } \
} while(0)
#endif

void RLogOpenStdio();
void RLogCloseStdio();
void RLogOpenSyslog();
void RLogOpenLogFile(const char *filename);
void RLogCloseLogFile();

} /* namespace clamfs */

#endif /* CLAMFS_RLOG_HXX */

/* EoF */
