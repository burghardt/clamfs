/*!\file config.cxx

   \brief Configuration file handling routines

   $Id: config.cxx,v 1.9 2008-11-23 20:50:00 burghardt Exp $

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2007,2008 Krzysztof Burghardt.

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

#include "config.hxx"

namespace clamfs {

extern config_t config;
extern extum_t* extensions;

ConfigParserXML::ConfigParserXML(const char *filename) {
    Open(filename);
#ifndef NDEBUG
    cout << "--- begin of xml dump ---" << endl;
#endif
    parse();
#ifndef NDEBUG
    cout << "--- end of xml dump ---" << endl;
#endif
}

ConfigParserXML::~ConfigParserXML() {
    Close();
}

void ConfigParserXML::Open(const char *filename) {
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

/*
 * Store configuration in clamfs::config and (if debug enabled)
 * dump parsed configuration file to cout
 */
void ConfigParserXML::startElement(const unsigned char *name, const unsigned char **attr) {
const unsigned char *option;
const unsigned char *value;
#ifndef NDEBUG
    cout << "<" << name;
#endif
    if(attr) {
        while(*attr) {
            option = *(attr++);
            value = *(attr++);
            if (strncmp((const char *)name, "exclude", 7) == 0) {
                if (extensions == NULL)
                    extensions = new extum_t;
                (*extensions)[(const char *)value] = whitelisted;
            } else if (strncmp((const char *)name, "include", 7) == 0) {
                if (extensions == NULL)
                    extensions = new extum_t;
                (*extensions)[(const char *)value] = blacklisted;
            } else
                config[strdup((const char *)option)] = strdup((const char *)value);
#ifndef NDEBUG
            cout << " " << option;
            cout << "=" << value;
#endif
        }
    }
#ifndef NDEBUG
    cout << ">" << endl;
#endif
}

/*
 * As long as our configuration file have no nested elements
 * we do not need to catch any element's end.
 */
void ConfigParserXML::endElement(const unsigned char *name) {
#ifndef NDEBUG
    cout << "</" << name << ">" << endl;
#endif
}

} /* namespace clamfs */

/* EoF */
