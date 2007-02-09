/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: clamav.cxx,v 1.5 2007-02-09 21:21:21 burghardt Exp $

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
    DEBUG("attempt to open control connection to clamd via %s", unixSocket); 

    clamd.open(unixSocket);
    CHECK_CLAMD(clamd);

    DEBUG("connected to clamd");
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

    DEBUG("got valid reply for PING command, clamd works");
    return 0;
}

/*
 * Close clamd collection
 */
void CloseClamav() {
    DEBUG("closing clamd connection");
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
    /* FIXME: PATH_MAX is obsolet on some systems and does not exist on other. */
    char reply[PATH_MAX + 1024];

    DEBUG("attempt to scan file %s", filename);

    /*
     * Enqueue requests
     */
    FastMutex::ScopedLock lock(scanMutex);

    /*
     * Open clamd socket
     */
    DEBUG("started scanning file %s", filename);
    OpenClamav(config["socket"]);
    if (!clamd) return -1;

    /*
     * Scan file using SCAN method
     */
    clamd << "SCAN " << filename << endl;
    clamd.getline(reply, PATH_MAX + 1024, '\n');
    CloseClamav();

    /*
     * Chceck for scan results
     */
    if (strncmp(reply + strlen(reply) - 2, "OK", 2) == 0 ||
	strncmp(reply + strlen(reply) - 10, "Empty file", 10) == 0) {
        DEBUG("%s", reply);
	return 0;
    }

    /*
     * Log result through rLog (if virus is found)
     */
    rLog(Warn, "%s", reply);

    /*
     * Send mail notification
     */
    SendMailNotification(config["server"], config["to"],
			 config["from"], config["subject"], reply);

    return 1;
}

} /* namespace clamfs */

/* EoF */
