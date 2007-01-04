/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2006 Krzysztof Burghardt.

   $Id: config.cxx,v 1.1.1.1 2007-01-04 02:22:47 burghardt Exp $

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

#include <config.hxx>

namespace clamfs {

ConfigParserXML::ConfigParserXML(char *filename) {
    Open(filename);
    parse();
}

ConfigParserXML::~ConfigParserXML() {
    Close();
}

void ConfigParserXML::Open(char *filename) {
    ifstream::open(filename);
}

void ConfigParserXML::Close(void) {
    ifstream::close();
}

int ConfigParserXML::read(unsigned char *buffer, size_t len) {
    ifstream::read((char *)buffer, len);
    len = gcount();
    return len;
}

void ConfigParserXML::startElement(const unsigned char *name, const unsigned char **attr) {
    cout << "<" << name;
    if(attr) {
	while(*attr) {
	    cout << " " << *(attr++);
	    cout << "=" << *(attr++);
	}
    }
    cout << ">" << endl;
}

void ConfigParserXML::endElement(const unsigned char *name) {
    cout << "</" << name << ">" << endl;
}

} /* namespace clamfs */

// EoF
