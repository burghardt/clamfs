/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: mnotify.hxx,v 1.1 2007-02-07 15:39:29 burghardt Exp $

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

#ifndef CLAMFS_MNOTIFY_HXX
#define CLAMFS_MNOTIFY_HXX

#include <config.h>

#include <Poco/Exception.h>
#include <Poco/Net/MailMessage.h>
#include <Poco/Net/MailRecipient.h>
#include <Poco/Net/SMTPClientSession.h>
#include <Poco/Net/StringPartSource.h>

#include <rlog.hxx>

namespace clamfs {

using namespace std;
using namespace Poco;
using namespace Poco::Net;

extern RLogChannel *Debug;
extern RLogChannel *Info;
extern RLogChannel *Warn;

int SendMailNotification(const char* mx, const char* recipient,
                         const char* sender, const char* subject,
			 const char* scanresult);

} /* namespace clamfs */

#endif /* CLAMFS_MNOTIFY_HXX */

/* EoF */