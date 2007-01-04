/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2006 Krzysztof Burghardt.

   $Id: clamav.cxx,v 1.1.1.1 2007-01-04 02:22:47 burghardt Exp $

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

#include <clamav.hxx>

namespace clamfs {

#define CHECK_CLAMD(clamdSocket) do {\
    if (!clamdSocket) {\
	rLog(Warn, "error: cannot connect to clamd");\
	return -1;\
    }\
} while(0)

unixstream clamd;

int OpenClamav(const char *unixSocket) {
    rLog(Debug, "attempt to open control connection to clamd via %s", unixSocket); 

    clamd.open(unixSocket);
    CHECK_CLAMD(clamd);

    rLog(Debug, "connected to clamd");
    return 0;
}

int PingClamav() {
    string reply;

    CHECK_CLAMD(clamd);   
    clamd << "PING" << endl;
    clamd >> reply;
    
    if (reply != "PONG") {
        rLog(Warn, "invalid reply for PING received: %s", reply.c_str());
	return -1;
    }

    rLog(Debug, "got valid reply for PING command, clamd works");
    return 0;
}

void CloseClamav() {
    rLog(Debug, "closing clamd connection");
    clamd.close();
}

int ClamavScanFile(const char *filename) {
    string reply;
    rLog(Debug, "attempt to scan file %s", filename);

    OpenClamav("/var/run/clamav/clamd.ctl");
    if (!clamd) return -1;

    clamd << "RAWSCAN " << filename << endl;
    clamd >> reply;
    clamd >> reply;
    CloseClamav();

    if (reply != "OK") {
        rLog(Warn, "%s IS INFECTED with %s", filename, reply.c_str());
	return 1;
    }

    rLog(Debug, "%s is OK", filename);
    return 0;
}

} /* namespace clamfs */

// EoF
