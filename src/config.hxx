/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2006 Krzysztof Burghardt.

   $Id: config.hxx,v 1.2 2007-01-13 21:06:52 burghardt Exp $

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

#ifndef CLAMFS_CONFIG_HXX
#define CLAMFS_CONFIG_HXX

#include <config.h>

#include <map>
#include <cc++/xml.h>

#include <utils.hxx>

namespace clamfs {

using namespace std;
using namespace ost;

class ConfigParserXML: public ifstream, public XMLStream {
    public:
	ConfigParserXML(const char *filename);
	~ConfigParserXML();
    protected:
	void Open(const char *filename);
	void Close(void);
    private:
	int read(unsigned char *buffer, size_t len);
	void startElement(const unsigned char *name, const unsigned char **attr);
	void endElement(const unsigned char *name);
	void characters(const unsigned char *text, size_t len) { }

};

} /* namespace clamfs */

#endif /* CLAMFS_CONFIG_HXX */

/* EoF */
