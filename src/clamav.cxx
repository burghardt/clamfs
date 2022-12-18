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

/* must be first because it may define _XOPEN_SOURCE */
#include "fdpassing.h"

#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/SocketStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/FileStream.h"
#include "Poco/File.h"

namespace clamfs {

extern config_t config;
extern FastMutex scanMutex;

/*!\def CHECK_CLAMD
   \brief Check if we are connected to clamd
   \param clamdStream SocketStream variable representing IO stream to check

   This macro is intended to easier to check if ClamFS is
   connected to clamd socket. This code check socket condition
   and if socket is not open returns -1.
*/
#define CHECK_CLAMD(clamdStream) do {\
    if (!clamdStream) {\
        poco_warning(logger, "error: clamd connection lost and unable to reconnect");\
        CloseClamav();\
        return -1;\
    }\
} while(0)

#ifdef HAVE_FD_PASSING
class ClamFStreamSocket: public StreamSocket {
    public:
        ssize_t sendFd(struct msghdr* msg) {
            return sendmsg(sockfd(), msg, 0);
        }
};
/*!\brief Custom stream socket used to communicate with clamd */
ClamFStreamSocket clamdSocket;
#else
/*!\brief POCO stream socket used to communicate with clamd */
StreamSocket clamdSocket;
#endif

/*!\brief Opens connection to clamd through unix socket
   \param unixSocket name of unix socket
   \returns 0 on success and -1 on failure
*/
int OpenClamav(const char *unixSocket) {
    SocketAddress sa(unixSocket);
    Logger& logger = Logger::root();

    poco_debug_f1(logger, "attempt to open connection to clamd via %s", string(unixSocket));
    try {
       clamdSocket.connect(sa);
    } catch (Exception &exc) {
       /* Ignore 'Socket is already connected' exception */
       if (exc.code() != EISCONN) {
         poco_warning_f2(logger, "error: unable to open connection to clamd: %s: %d",
               exc.displayText(), exc.code());
         return -1;
       }
    }
    SocketStream clamd(clamdSocket);
    CHECK_CLAMD(clamd);

    poco_debug(logger, "connected to clamd");
    return 0;
}

/*!\brief Check clamd availability by sending PING command and checking the reply
*/
int PingClamav() {
    string reply;
    Logger& logger = Logger::root();

    SocketStream clamd(clamdSocket);
    CHECK_CLAMD(clamd);
    clamd << "nPING" << endl;
    clamd >> reply;

    if (reply != "PONG") {
        poco_warning_f1(logger, "invalid reply for PING received: %s", reply);
        return -1;
    }

    poco_debug(logger, "got valid reply for PING command, clamd works");
    return 0;
}

/*!\brief Close clamd connection
*/
void CloseClamav() {
    Logger& logger = Logger::root();

    poco_debug(logger, "closing clamd connection");
    clamdSocket.close();
}

#ifdef HAVE_FD_PASSING
/*!\brief Send file descriptor over clamd connection
   \param fd file descriptor to pass to clamd
 */
static void SendFileDescriptorForFile(const int fd) {
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[]   = "";

    iov[0].iov_base = dummy;
    iov[0].iov_len  = 1;

    memset(&msg, 0, sizeof(msg));
    msg.msg_control    = fdbuf;
    msg.msg_iov        = iov;
    msg.msg_iovlen     = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));
    cmsg               = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len     = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level   = SOL_SOCKET;
    cmsg->cmsg_type    = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    clamdSocket.sendFd(&msg);
}
#endif

/*!\brief Request anti-virus scanning on file
   \param filename name of file to scan
   \returns -1 one error when opening clamd connection,
             0 if no virus found and
             1 if virus was found (or clamd error occurred)
 */
int ClamavScanFile(const char *filename) {
    string reply;
    Logger& logger = Logger::root();

    poco_debug_f1(logger, "attempt to scan file %s", string(filename));

    /*
     * Enqueue requests
     */
    FastMutex::ScopedLock lock(scanMutex);

    /*
     * Open clamd socket
     */
    poco_debug_f1(logger, "started scanning file %s", string(filename));
    OpenClamav(config["socket"]);
    SocketStream clamd(clamdSocket);
    if (!clamd)
        return -1;

    if ((config["mode"] != NULL) &&
        strncmp(config["mode"], "fdpass", 6) == 0) {
#ifdef HAVE_FD_PASSING
        /*
         * Scan file using FILDES command
         */
        int fd = open(filename, O_RDONLY);
        if (fd >= 0) {
            clamd << "nFILDES"<< endl << flush;
            SendFileDescriptorForFile(fd);
            close(fd);
        } else {
            poco_warning_f1(logger, "Unable to pass fd for file '%s'", string(filename));
            return -1;
        }
#else
        poco_warning(logger, "Scan command FILDES not available due to lack of fd passing.");
        return -1;
#endif
    } else if ((config["mode"] != NULL) &&
               strncmp(config["mode"], "stream", 6) == 0) {
        /*
         * Scan file using INSTREAM command
         */
        FileInputStream istr(filename, std::ios::binary);
        if (istr.good()) {
            std::string chunkSizeStr;
            File f(filename);
            size_t chunkSize = htonl(f.getSize());

            chunkSizeStr.assign((const char*)&chunkSize, 4);
            clamd << "nINSTREAM" << endl;
            clamd << chunkSizeStr;
            StreamCopier::copyStream(istr, clamd);
            chunkSizeStr.assign("\0\0\0\0", 4);
            clamd << chunkSizeStr << flush;
        } else {
            poco_warning_f1(logger, "Unable to pass stream for file '%s'", string(filename));
            return -1;
        }
    } else {
        /*
         * Scan file using SCAN command
         */
        clamd << "nSCAN " << filename << endl;
    }

    /*
     * Receive results and close stream
     */
    getline(clamd, reply);
    CloseClamav();

    /*
     * Check for scan results, return if file is clean
     */
    poco_debug_f2(logger, "clamd reply for file '%s' is: '%s'", string(filename), reply);
    if (strncmp(reply.c_str() + reply.size() - 2,  "OK", 2) == 0 ||
        strncmp(reply.c_str() + reply.size() - 10, "Empty file", 10) == 0 ||
        strncmp(reply.c_str() + reply.size() - 8,  "Excluded", 8) == 0 ||
        strncmp(reply.c_str() + reply.size() - 29, "Excluded (another filesystem)", 29) == 0 ) {
        return 0;
    }

    /*
     * Log result through Logger (if virus is found or scan failed)
     */
    char* username = getusername();
    char* callername = getcallername();
    poco_warning_f(logger, "(%s:%d) (%s:%u) '%s': %s", string(callername), fuse_get_context()->pid,
        string(username), fuse_get_context()->uid, string(filename),
        reply.empty() ? "< empty clamd reply >" : reply);
    free(username);
    free(callername);

    /*
     * If reply was empty or no reply was received
     * return without any interpretation of reply
     */
    if (reply.empty())
       return -1;

    /*
     * If scan failed return without sending e-mail alert
     */
    if (strncmp(reply.c_str() + reply.size() - 20, "Access denied. ERROR", 20) == 0 ||
       strncmp(reply.c_str() + reply.size() - 21, "lstat() failed. ERROR", 21) == 0 ||
       strncmp(reply.c_str() + reply.size() - 40, "lstat() failed: Permission denied. ERROR", 40) == 0 ||
       strncmp(reply.c_str() + reply.size() - 48, "lstat() failed: No such file or directory. ERROR", 48) == 0 ||
       strncmp(reply.c_str() + reply.size() - 34, "No file descriptor received. ERROR", 34) == 0 ||
       strncmp(reply.c_str() + reply.size() - 35, "INSTREAM size limit exceeded. ERROR", 35) == 0) {
        return -1;
    }

    if (strncmp(reply.c_str() + reply.size() - 5, "FOUND", 5) != 0) {
       poco_warning(logger, "Response not ending with 'FOUND' was received and left uninterpreted!");
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
