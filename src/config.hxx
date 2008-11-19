/*!\file config.hxx

   \brief Configuration file handling routines (header file)

   $Id: config.hxx,v 1.8 2008-11-19 21:55:32 burghardt Exp $

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2007 Krzysztof Burghardt.

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
#include <ext/hash_map>
#include <cc++/xml.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include <utils.hxx>

namespace clamfs {

using namespace std;
/*!\namespace __gnu_cxx
   \brief GNU C++ namespace
*/
using namespace __gnu_cxx;
/*!\namespace ost
   \brief GNU CommonC++ namespace
*/
using namespace ost;

/*!\enum acl_item
   \brief Enumeration of Access List Items
*/
enum acl_item { none = 0, blacklisted, whitelisted };

/*!\typedef exthm_t
   \brief Extension Hash Map
*/
typedef hash_map <const char*, acl_item, hash <const char*>, eqstr> exthm_t;

/*!\typedef config_t
   \brief ClamFS Configuration
*/
typedef map <const char *, char *, ltstr> config_t;

/*!\class ConfigParserXML
   \brief Config pareser parses configuration file and stores configuration in clamfs::config
*/
class ConfigParserXML: public ifstream, public XMLStream {
    public:
        /*!\brief Constructor for ConfigParserXML
           \param filename configuration file name
        */
        ConfigParserXML(const char *filename);
        /*!\brief Destructor for ConfigParserXML */
        ~ConfigParserXML();
    protected:
        /*!\brief Opens configuration file
           \param filename configuration file name
        */
        void Open(const char *filename);
        /*!\brief Closes configuration file*/
        void Close(void);
    private:
        /*!\brief XMLStream virtual method called to read data
           \param buffer buffer to read from
           \param len how many characters to read
           \returns how many characters was read
         */
        int read(unsigned char *buffer, size_t len);
        /*!\brief XMLStream virtual method called at element start
           \param name name of element beginning precessed
           \param attr NULL terminated array of its atributes and their values
        */
        void startElement(const unsigned char *name, const unsigned char **attr);
        /*!\brief XMLStream virtual method called at element end
           \param name name of element which end was reached
         */
        void endElement(const unsigned char *name);
        /*!\brief Empty XMLStream virtual method, we do not need it */
        void characters(const unsigned char *text, size_t len) { }
    private:
        /*!brief Forbid usage of copy constructor */
        ConfigParserXML(const ConfigParserXML& aCache);
        /*!brief Forbid usage of assignment operator */
        ConfigParserXML& operator = (const ConfigParserXML& aCache);
};

} /* namespace clamfs */

#endif /* CLAMFS_CONFIG_HXX */

/* EoF */
