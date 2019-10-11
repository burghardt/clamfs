/*!\file rlog.cxx

   \brief RLog logging routines

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

#include "rlog.hxx"

#include <unistd.h>

namespace clamfs {

extern config_t config;

/*!\brief Debug channel (debugging messages goes here) */
RLogChannel *Debug = DEF_CHANNEL("debug", Log_Debug);
/*!\brief Information channel (most messages goes here) */
RLogChannel *Info = DEF_CHANNEL("info", Log_Info);
/*!\brief Warning channel (warnings goes here) */
RLogChannel *Warn = DEF_CHANNEL("warn", Log_Warning);

/*!\brief Stdout logging node */
static StdioNode *stdLog = NULL;
/*!\brief Syslog logging node */
static SyslogNode *logNode = NULL;
/*!\brief Log file descriptor */
static int fileLog = 0;
/*!\brief Log file logging node */
static StdioNode *fileLogNode = NULL;

/*!\brief Opens stdio logging target

   This function opens stdio logging target
   and subscribes all RLog channels for it.
*/
void RLogOpenStdio() {
#ifndef NDEBUG
    stdLog = new StdioNode(STDOUT_FILENO, StdioNode::OutputContext |
    StdioNode::OutputThreadId | StdioNode::OutputColor);
#else
    stdLog = new StdioNode(STDOUT_FILENO);
#endif
    stdLog->subscribeTo( RLOG_CHANNEL("") );
    DEBUG("initial log attached to stdio");
}

/*!\brief Closes stdio logging target
*/
void RLogCloseStdio() {
    DEBUG("will close initial stdio log");
    delete stdLog;
    stdLog = NULL;
    DEBUG("closed initial stdio log");
}

/*!\brief Opens syslog logging target

   This function opens syslog logging target
   and subscribes all RLog channels for it.
*/
void RLogOpenSyslog() {
    logNode = new SyslogNode("clamfs");
    logNode->subscribeTo( RLOG_CHANNEL("") );
    rLog(Info, "logs goes to syslog");
}

/*!\brief Opens log file logging target
   \param filename log file name

   This function opens log file logging target
   and subscribes all RLog channels for it.
*/
void RLogOpenLogFile(const char *filename) {
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    fileLog = open(filename, O_WRONLY | O_CREAT | O_APPEND, mode);
    if (fileLog > 0) { /* file open successful */
#ifndef NDEBUG
        fileLogNode = new StdioNode(fileLog, StdioNode::OutputContext |
        StdioNode::OutputThreadId);
#else
        fileLogNode = new StdioNode(fileLog);
#endif
        fileLogNode->subscribeTo( RLOG_CHANNEL("") );
        rLog(Info, "log goes to file %s", filename);
    } else { /* file open failed */
        rLog(Warn, "cannot open log file %s", filename);
        exit(EXIT_FAILURE);
    }
}

/*!\brief Closes log file logging target
*/
void RLogCloseLogFile() {
    if (fileLog > 0) { /* file open, close it */
        delete fileLogNode;
        fileLogNode = NULL;
        close(fileLog);
    }
}

} /* namespace clamfs */

/* EoF */
