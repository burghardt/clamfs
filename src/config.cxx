/*!\file config.cxx

   \brief Configuration file handling routines

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2007-2024 Krzysztof Burghardt

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

#include <iostream>

namespace clamfs {

extern config_t config;
extern extum_t* extensions;

ConfigParserXML::ConfigParserXML(const char *filename) {
    ConfigHandler handler;
    SAXParser parser;

#ifndef NDEBUG
    cout << "--- begin of xml dump ---" << endl;
#endif
    parser.setFeature(XMLReader::FEATURE_NAMESPACES, true);
    parser.setFeature(XMLReader::FEATURE_NAMESPACE_PREFIXES, true);

    // Disable external entity resolution
    parser.setFeature(XMLReader::FEATURE_EXTERNAL_GENERAL_ENTITIES, false);
    parser.setFeature(XMLReader::FEATURE_EXTERNAL_PARAMETER_ENTITIES, false);

    parser.setContentHandler(&handler);
    try {
       parser.parse(filename);
    } catch (Exception &e) {
       Logger& logger = Logger::get("consoleLogger");
       poco_warning(logger, e.displayText().c_str());
    }
#ifndef NDEBUG
    cout << "--- end of xml dump ---" << endl;
#endif
}

/*
 * Store configuration in clamfs::config and (if debug enabled)
 * dump parsed configuration file to cout
 */
void ConfigHandler::startElement(const XMLString& uri, const XMLString& localName, const XMLString& qname, const Attributes& attributes) {
    (void)uri;
    (void)localName;
#ifndef NDEBUG
    cout << "<" << qname;
#endif
    for(int i = 0; i < attributes.getLength(); ++i) {
        const char *option;
        const char *value;
        option = attributes.getLocalName(i).c_str();
        value = attributes.getValue(i).c_str();
        if (qname.compare("exclude") == 0) {
            if (extensions == NULL)
                extensions = new extum_t;
            (*extensions)[(const char *)value] = whitelisted;
        } else if (qname.compare("include") == 0) {
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
#ifndef NDEBUG
    cout << ">" << endl;
#endif
}

/*
 * As long as our configuration file have no nested elements
 * we do not need to catch any element's end.
 */
void ConfigHandler::endElement(const XMLString & uri, const XMLString & localName, const XMLString & qname) {
    (void)uri;
    (void)localName;
#ifndef NDEBUG
    cout << "</" << qname << ">" << endl;
#else
    (void)qname;
#endif
}

} /* namespace clamfs */

/* EoF */
