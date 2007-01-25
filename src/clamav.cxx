/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2006 Krzysztof Burghardt.

   $Id: clamav.cxx,v 1.3 2007-01-25 02:51:29 burghardt Exp $

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

extern map <const char *, char *, ltstr> config;
extern FastMutex scanMutex;

/*
 * Check if we can connect co clamd
 */
#define CHECK_CLAMD(clamdSocket) do {\
    if (!clamdSocket) {\
	rLog(Warn, "error: cannot connect to clamd");\
	return -1;\
    }\
} while(0)

unixstream clamd;

/*
 * Open connection to clamd through unix socket
 */
int OpenClamav(const char *unixSocket) {
    rLog(Debug, "attempt to open control connection to clamd via %s", unixSocket); 

    clamd.open(unixSocket);
    CHECK_CLAMD(clamd);

    rLog(Debug, "connected to clamd");
    return 0;
}

/*
 * Check clamd availability by sending PING command and checking for reply
 */
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

/*
 * Close clamd collection
 */
void CloseClamav() {
    rLog(Debug, "closing clamd connection");
    clamd.close();
}

/*
 * Request anti virus scanning on file
 *
 * return: -1 - error opening clamd connection
 *          0 - OK (no virus found)
 *          1 - virus found or error
 */
int ClamavScanFile(const char *filename) {
    char reply[PATH_MAX + 1024];

    rLog(Debug, "attempt to scan file %s", filename);

    /*
     * Enqueue requests
     */
    FastMutex::ScopedLock lock(scanMutex);

    OpenClamav(config["socket"]);
    if (!clamd) return -1;

    clamd << "RAWSCAN " << filename << endl;
    clamd.getline(reply, PATH_MAX + 1024, '\n');
    CloseClamav();

    if (strncmp(reply + strlen(reply) - 2, "OK", 2) == 0 ||
	strncmp(reply + strlen(reply) - 10, "Empty file", 10) == 0) {
        rLog(Debug, "%s", reply);
	return 0;
    }

    rLog(Warn, "%s", reply);
    return 1;
}

} /* namespace clamfs */

/* EoF */
