/*!\file clamav.cxx

   \brief Clamd bindings

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

#include "clamav.hxx"

#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/SocketStream.h"
#include "Poco/StreamCopier.h"

namespace clamfs {

extern config_t config;
extern FastMutex scanMutex;

/*!\def CHECK_CLAMD
   \brief Check if we are connected to clamd
   \param clamdSocket unixstream variable representing socket

   This macro is intended to easier to check if ClamFS is
   connected to clamd socket. This code check socket condition
   and if socket is not open returns -1.
*/
#define CHECK_CLAMD(clamdStream) do {\
    if (!clamdStream) {\
        rLog(Warn, "error: clamd connection lost and unable to reconnect");\
        CloseClamav();\
        return -1;\
    }\
} while(0)

/*!\brief Unix socket used to communicate with clamd */
StreamSocket clamdSocket;

/*!\brief Opens connection to clamd through unix socket
   \param unixSocket name of unix socket
   \returns 0 on success and -1 on failure
*/
int OpenClamav(const char *unixSocket) {
    SocketAddress sa(unixSocket);

    DEBUG("attempt to open connection to clamd via %s", unixSocket);
    try {
       clamdSocket.connect(sa);
    } catch (Exception &e) {
       rLog(Warn, "error: unable to open connection to clamd");
       return -1;
    }
    SocketStream clamd(clamdSocket);
    CHECK_CLAMD(clamd);

    DEBUG("connected to clamd");
    return 0;
}

/*!\brief Check clamd availability by sending PING command and checking the reply
*/
int PingClamav() {
    string reply;

    SocketStream clamd(clamdSocket);
    CHECK_CLAMD(clamd);
    clamd << "nPING" << endl;
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
    clamdSocket.close();
}

/*!\brief Request anti-virus scanning on file
   \param filename name of file to scan
   \returns -1 one error when opening clamd connection,
             0 if no virus found and
             1 if virus was found (or clamd error occurred)
 */
int ClamavScanFile(const char *filename) {
    string reply;

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
    SocketStream clamd(clamdSocket);
    if (!clamd)
        return -1;

    /*
     * Scan file using SCAN method
     */
    clamd << "nSCAN " << filename << endl;
    getline(clamd, reply);
    CloseClamav();

    /*
     * Chceck for scan results, return if file is clean
     */
    DEBUG("clamd reply is: '%s'", reply.c_str());
    if (strncmp(reply.c_str() + reply.size() - 2,  "OK", 2) == 0 ||
        strncmp(reply.c_str() + reply.size() - 10, "Empty file", 10) == 0 ||
        strncmp(reply.c_str() + reply.size() - 8,  "Excluded", 8) == 0 ||
        strncmp(reply.c_str() + reply.size() - 29, "Excluded (another filesystem)", 29) == 0 ) {
        return 0;
    }

    /*
     * Log result through RLog (if virus is found or scan failed)
     */
    char* username = getusername();
    char* callername = getcallername();
    rLog(Warn, "(%s:%d) (%s:%d) %s", callername, fuse_get_context()->pid,
        username, fuse_get_context()->uid, reply.empty() ? "< empty clamd reply >" : reply.c_str());
    free(username);
    free(callername);

    /*
     * If scan failed return without sending e-mail alert
     */
    if(strncmp(reply.c_str() + reply.size() - 20, "Access denied. ERROR", 20) == 0 ||
       strncmp(reply.c_str() + reply.size() - 21, "lstat() failed. ERROR", 21) == 0) {
        return -1;
    }

    /*
     * Send mail notification
     */
    SendMailNotification(config["server"], config["to"],
             config["from"], config["subject"], reply.c_str());

    return 1;
}

} /* namespace clamfs */

/* EoF */
