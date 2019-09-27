/*!\file config.hxx

   \brief Configuration file handling routines (header file)

   $Id: config.hxx,v 1.13 2008-12-06 14:29:54 burghardt Exp $

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

#ifndef CLAMFS_CONFIG_HXX
#define CLAMFS_CONFIG_HXX

#include "config.h"

#include <map>
#include <tr1/unordered_map>
#include <Poco/SAX/SAXParser.h>
#include <Poco/SAX/ContentHandler.h>
#include <Poco/SAX/LexicalHandler.h>
#include <Poco/SAX/Attributes.h>
#include <Poco/SAX/Locator.h>
#include <Poco/Exception.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "utils.hxx"

namespace clamfs {

/*!\namespace std
   \brief STanDard namespace
*/
using namespace std;

/*!\namespace tr1
   \brief ISO/IEC TR 19768 namespace
*/
using namespace tr1;

/*!\namespace Poco::XML
   \brief Poco library XML parser namespace
*/
using namespace Poco::XML;

/*!\enum acl_item
   \brief Enumeration of Access List Items
*/
enum acl_item { none = 0, blacklisted, whitelisted };

/*!\typedef extum_t
   \brief Extension Unordered Map
*/
typedef unordered_map <string, acl_item> extum_t;

/*!\typedef config_t
   \brief ClamFS Configuration
*/
typedef map <const char *, char *, ltstr> config_t;

/*!\class ConfigHandler
   \brief Config handler handles events from ContentHandler and fills in clamfs::config
*/
class ConfigHandler: public ContentHandler { //, public LexicalHandler {
   public:
      /*!\brief Constructor for ConfigHandler */
      ConfigHandler() { };
      /*!\brief Destructor for ConfigHandler */
      virtual ~ConfigHandler() { };
   protected:
       /**@{*/
       /*!\brief Funcions inherited from Poco::XML::ContentHandler */
        virtual void setDocumentLocator(const Poco::XML::Locator *loc) { (void)loc; }
        virtual void startDocument() { }
        virtual void endDocument() { }
        virtual void startElement(const XMLString& uri, const XMLString& localName, const XMLString& qname, const Attributes& attributes);
        virtual void endElement(const XMLString & uri, const XMLString & localName, const XMLString & qname);
        virtual void characters(const XMLChar ch[], int start, int length) { (void)ch, (void)start, (void)length; }
        virtual void ignorableWhitespace(const XMLChar ch[], int start, int length) { (void)ch, (void)start, (void)length; }
        virtual void processingInstruction(const XMLString& target, const XMLString& data) { (void)target; (void)data; }
        virtual void skippedEntity(const XMLString& name) { (void)name; }
        virtual void startPrefixMapping(const Poco::XML::XMLString& prefix, const Poco::XML::XMLString& uri) { (void)prefix; (void)uri; }
        virtual void endPrefixMapping(const Poco::XML::XMLString& prefix) { (void)prefix; }
        /**@}*/
    private:
        /*!brief Forbid usage of copy constructor */
        ConfigHandler(const ConfigHandler& aConfigHandler);
        /*!brief Forbid usage of assignment operator */
        ConfigHandler& operator = (const ConfigHandler& aConfigHandler);
};

/*!\class ConfigParserXML
   \brief Config pareser parses configuration file and stores configuration in clamfs::config
*/
class ConfigParserXML {
    public:
        /*!\brief Constructor for ConfigParserXML
           \param filename configuration file name
        */
        ConfigParserXML(const char *filename);
        /*!\brief Destructor for ConfigParserXML */
        virtual ~ConfigParserXML() { };
    private:
        /*!brief Forbid usage of copy constructor */
        ConfigParserXML(const ConfigParserXML& aConfigParserXML);
        /*!brief Forbid usage of assignment operator */
        ConfigParserXML& operator = (const ConfigParserXML& aConfigParserXML);
};

} /* namespace clamfs */

#endif /* CLAMFS_CONFIG_HXX */

/* EoF */
