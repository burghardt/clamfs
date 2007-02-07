/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: rlog.cxx,v 1.3 2007-02-07 15:39:29 burghardt Exp $

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
static int fileLog=0;                                                                                
static StdioNode* fileLogNode=NULL;                                                                  

void RLogOpenStdio() {
    stdLog = new StdioNode(STDOUT_FILENO);
    stdLog->subscribeTo( RLOG_CHANNEL("") );
    rLog(Debug, "initial log attached to stdio");
}

void RLogCloseStdio() {
    rLog(Debug, "will close initial stdio log");
    delete stdLog;
    stdLog = NULL;
    rLog(Debug, "closed initial stdio log");
}

void RLogOpenSyslog() {
    logNode = new SyslogNode( "clamfs" );
    logNode->subscribeTo( RLOG_CHANNEL("") );
    rLog(Info, "logs goes to syslog");
}

void RLogOpenLogFile(const char *filename) {
    fileLog = open(filename, O_WRONLY|O_CREAT|O_APPEND);
    fileLogNode = new StdioNode(fileLog);
    fileLogNode->subscribeTo( RLOG_CHANNEL("") );
    rLog(Info, "log goes to file %s", filename);
}

} /* namespace clamfs */

/* EoF */
