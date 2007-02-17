/*!\file clamav.cxx

   \brief Clamd bindings

   $Id: clamav.cxx,v 1.7 2007-02-17 20:58:11 burghardt Exp $

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2007 Krzysztof Burghardt.

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

/*!\def CHECK_CLAMD
   \brief Check if we are connected to clamd
   \param clamdSocket unixstream variable representing socket
   
   This macro is intended to easier to check if ClamFS is
   connected to clamd socket. This code check socket condition
   and if socket is not open returns -1.
*/
#define CHECK_CLAMD(clamdSocket) do {\
    if (!clamdSocket) {\
	rLog(Warn, "error: cannot connect to clamd");\
	return -1;\
    }\
} while(0)

/*!\brief Unix socket used to communicate with clamd */
unixstream clamd;

/*!\brief Opens connection to clamd through unix socket
   \param unixSocket name of unix socket
   \returns 0 on success and -1 on failure
*/
int OpenClamav(const char *unixSocket) {
    DEBUG("attempt to open control connection to clamd via %s", unixSocket); 

    clamd.open(unixSocket);
    CHECK_CLAMD(clamd);

    DEBUG("connected to clamd");
    return 0;
}

/*!\brief Check clamd availability by sending PING command and checking the reply
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

/*!\brief Close clamd connection
*/
void CloseClamav() {
    DEBUG("closing clamd connection");
    clamd.close();
}

/*!\brief Request anti-virus scanning on file
   \param filename name of file to scan
   \returns -1 one error when opening clamd connection,
             0 if no virus found and
	     1 if virus was found (or clamd error occurred)
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
     * Log result through RLog (if virus is found)
     */
    rLog(Warn, "(%s:%d) (%s:%d) %s", getcallername(), fuse_get_context()->pid,
	getusername(), fuse_get_context()->uid, reply);

    /*
     * Send mail notification
     */
    SendMailNotification(config["server"], config["to"],
			 config["from"], config["subject"], reply);

    return 1;
}

} /* namespace clamfs */

/* EoF */
