/*!\file logger.cxx

   \brief Logger logging routines

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

#include <cstdlib>

#include "logger.hxx"

#include <unistd.h>

namespace clamfs {

extern config_t config;

/*!\brief Opens stdio logging target

   This function opens stdio logging target
   and subscribes all Logger channels for it.
*/
void LoggerOpenStdio() {
    Logger& logger = Logger::root();
#ifndef NDEBUG
    AutoPtr<PatternFormatter> fmt(new PatternFormatter("%H:%M:%S (%O:%u) [tid:%I] %t"));
#else
    AutoPtr<PatternFormatter> fmt(new PatternFormatter("%H:%M:%S (%O:%u) %t"));
#endif
    AutoPtr<FormattingChannel> fmtChan(new FormattingChannel(fmt, new ColorConsoleChannel));
    logger.setChannel(fmtChan);
    logger.setLevel(Message::PRIO_DEBUG);
    poco_debug(logger, "initial log attached to stdio");
}

/*!\brief Opens syslog logging target

   This function opens syslog logging target
   and subscribes all Logger channels for it.
*/
void LoggerOpenSyslog() {
    Logger& logger = Logger::root();
    logger.setChannel(new SyslogChannel("clamfs",
        SyslogChannel::SYSLOG_PID,
        SyslogChannel::SYSLOG_LOCAL4));
    poco_information(logger, "logs goes to syslog");
}

/*!\brief Opens log file logging target
   \param filename log file name

   This function opens log file logging target
   and subscribes all Logger channels for it.
*/
void LoggerOpenLogFile(const string &filename) {
    Logger& logger = Logger::root();
#ifndef NDEBUG
    AutoPtr<PatternFormatter> fmt(new PatternFormatter("%H:%M:%S (%O:%u) [tid:%I] %t"));
#else
    AutoPtr<PatternFormatter> fmt(new PatternFormatter("%H:%M:%S (%O:%u) %t"));
#endif
    AutoPtr<SimpleFileChannel> pChannel(new SimpleFileChannel);
    pChannel->setProperty("path", filename);

    AutoPtr<FormattingChannel> fmtChan(new FormattingChannel(fmt, pChannel));
    logger.setChannel(fmtChan);
    logger.setLevel(Message::PRIO_DEBUG);

    try {
        poco_information_f1(logger, "logs goes to file %s", filename);
    } catch (Poco::FileException &exc) {
       LoggerOpenStdio();
       poco_warning_f2(logger, "cannot open log file %s: %s", filename, exc.displayText());
       exit(EXIT_FAILURE);
    }
}

} /* namespace clamfs */

/* EoF */
