/*!\file clamav.hxx

   \brief Clamd bindings (header file)

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

#ifndef CLAMFS_CLAMAV_HXX
#define CLAMFS_CLAMAV_HXX

#include "config.h"

#include <cstring>
#include <Poco/Mutex.h>
#include <Poco/ScopedLock.h>

#ifdef DMALLOC
#include <malloc.h>
#include <dmalloc.h>
#endif

#include "config.hxx"
#include "rlog.hxx"
#include "mnotify.hxx"

namespace clamfs {

using namespace std;
using namespace Poco;
using namespace Poco::Net;

extern RLogChannel *Debug;
extern RLogChannel *Info;
extern RLogChannel *Warn;

int OpenClamav(const char *unixSocket);
int PingClamav();
void CloseClamav();
int ClamavScanFile(const char *filename);

} /* namespace clamfs */

#endif /* CLAMFS_CLAMAV_HXX */

/* EoF */
