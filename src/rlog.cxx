/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: rlog.cxx,v 1.4 2007-02-09 21:21:21 burghardt Exp $

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

#include <rlog.hxx>

namespace clamfs {

RLogChannel *Debug = DEF_CHANNEL("debug", Log_Debug);
RLogChannel *Info = DEF_CHANNEL("info", Log_Info);
RLogChannel *Warn = DEF_CHANNEL("warn", Log_Warning);

static StdioNode *stdLog = NULL;
static SyslogNode *logNode = NULL;
static int fileLog = 0;
static StdioNode *fileLogNode = NULL;

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

void RLogCloseStdio() {
    DEBUG("will close initial stdio log");
    delete stdLog;
    stdLog = NULL;
    DEBUG("closed initial stdio log");
}

void RLogOpenSyslog() {
    logNode = new SyslogNode("clamfs");
    logNode->subscribeTo( RLOG_CHANNEL("") );
    rLog(Info, "logs goes to syslog");
}

void RLogOpenLogFile(const char *filename) {
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    fileLog = open(filename, O_WRONLY | O_CREAT | O_APPEND, mode);
    if (fileLog > 0) { /* file open succesful */
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

void RLogCloseLogFile() {
    if (fileLog > 0) { /* file open, close it */
	delete fileLogNode;
	fileLogNode = NULL;
	close(fileLog);
    }
}

} /* namespace clamfs */

/* EoF */
