/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: mnotify.cxx,v 1.1 2007-02-07 15:39:29 burghardt Exp $

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

#include <mnotify.hxx>

namespace clamfs {

/*
 * Sends mail with notification message
 * (returns 0 on success or -1 on smtp error
 *  and -2 on insufficient parameters)
 */
int SendMailNotification(const char* mx, const char* recipient,
                         const char* sender, const char* subject,
			 const char* scanresult) {
    /*
     * Check if all parameters are defined
     */
    if ((mx == NULL) ||
        (recipient == NULL) ||
	(sender == NULL) ||
	(subject == NULL) ||
	(scanresult == NULL))
	return -2;

    /*
     * Try to send message
     */
    try {
	MailMessage mmsg;
	string body;

        mmsg.setSender(sender);
	mmsg.addRecipient(MailRecipient(MailRecipient::PRIMARY_RECIPIENT, recipient));
	mmsg.setSubject(subject);

	body += "Hello ClamFS User,\r\n\r\n";
	body += "This is an automatic notification about virus found.\r\n\r\n";
	body += "ClamAV reported malicious file:\r\n";
	body += scanresult;
	
	mmsg.addContent(new StringPartSource(body));

	SMTPClientSession session(mx);
	session.login();
	session.sendMessage(mmsg);
	session.close();
    } catch (Exception& exc) {
	rLog(Debug, "Got exception when sending mail notification: %s", exc.displayText().c_str());
	return 1;
    }

    return 0;
}

} /* namespace clamfs */

/* EoF */
