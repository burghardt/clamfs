/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: rlog.hxx,v 1.3 2007-02-07 15:39:29 burghardt Exp $

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

#include <config.h>

#include <cc++/file.h>

#include <rlog/rlog.h>
#include <rlog/Error.h>
#include <rlog/RLogChannel.h>
#include <rlog/SyslogNode.h>
#include <rlog/StdioNode.h>

namespace clamfs {

using namespace std;
using namespace rlog;

void RLogOpenStdio();
void RLogCloseStdio();
void RLogOpenSyslog();
void RLogOpenLogFile(const char *filename);

} /* namespace clamfs */

#endif /* CLAMFS_RLOG_HXX */

/* EoF */
