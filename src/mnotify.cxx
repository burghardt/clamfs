/*!\file mnotify.cxx

   \brief Mail notification routines

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

#include "mnotify.hxx"

namespace clamfs {

static const char* crlf = "\r\n";

/*!\brief Send notification e-mail message
   \param mx mail exchanger (server)
   \param recipient To: address
   \param sender From: address
   \param subject Subject: header
   \param scanresult message from clamd
   \returns 0 on success or -1 on smtp error and -2 on insufficient parameters
*/
int SendMailNotification(const char* mx, const char* recipient,
                         const char* sender, const char* subject,
                         const char* scanresult)
{
    char* username;
    char* callername;

    /*
     * Check if all parameters are defined
     */
    if ((mx == NULL) ||
        (recipient == NULL) ||
        (sender == NULL) ||
        (subject == NULL) ||
        (scanresult == NULL))
        return -2;

    username = getusername();
    callername = getcallername();

    /*
     * Try to send message
     */
    try {
        MailMessage mmsg;
        stringstream body;

        mmsg.setSender(sender);
        mmsg.addRecipient(MailRecipient(MailRecipient::PRIMARY_RECIPIENT, recipient));
        mmsg.setSubject(subject);

        body << "Hello ClamFS User," << crlf << crlf;
        body << "This is an automatic notification about virus found." << crlf << crlf;
        body << "Executable name: " << callername << crlf;
        body << "            PID: " << fuse_get_context()->pid << crlf << crlf;
        body << "       Username: " << username << crlf;
        body << "            UID: " << fuse_get_context()->uid << crlf << crlf;
        body << "ClamAV reported malicious file:" << crlf;
        body << scanresult << crlf;

        mmsg.setContent(body.str());

        SMTPClientSession session(mx);
        session.login();
        session.sendMessage(mmsg);
        session.close();
    } catch (Poco::Exception& exc) {
        rLog(Info, "Got exception when sending mail notification: %s", exc.displayText().c_str());

        free(username);
        free(callername);

        return 1;
    }

    free(username);
    free(callername);

    return 0;
}

} /* namespace clamfs */

/* EoF */
