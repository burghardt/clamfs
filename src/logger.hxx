/*!\file logger.hxx

   \brief Poco::Logger logging routines (header file)

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2022 Krzysztof Burghardt

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

#ifndef CLAMFS_LOGGER_HXX
#define CLAMFS_LOGGER_HXX

#include "config.h"

#include <cstring>
#include <Poco/Exception.h>
#include <Poco/Logger.h>
#include <Poco/FormattingChannel.h>
#include <Poco/PatternFormatter.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/SyslogChannel.h>
#include <Poco/SimpleFileChannel.h>

#ifdef DMALLOC
   #include <stdlib.h>
   #ifdef HAVE_MALLOC_H
      #include <malloc.h>
   #endif
   #include <dmalloc.h>
#endif

#include "config.hxx"
#include "utils.hxx"

namespace clamfs {

using namespace std;
using Poco::ColorConsoleChannel;
using Poco::SyslogChannel;
using Poco::SimpleFileChannel;
using Poco::FormattingChannel;
using Poco::PatternFormatter;
using Poco::Logger;
using Poco::Message;
using Poco::AutoPtr;

void LoggerOpenStdio();
void LoggerOpenSyslog();
void LoggerOpenLogFile(const string &filename);

} /* namespace clamfs */

#endif /* CLAMFS_LOGGER_HXX */

/* EoF */
