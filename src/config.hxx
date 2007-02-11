/*!\file config.hxx

   \brief Configuration file handling routines (header file)

   $Id: config.hxx,v 1.5 2007-02-11 01:31:11 burghardt Exp $

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
#include <cc++/xml.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include <utils.hxx>

namespace clamfs {

using namespace std;
/*!\namespace ost
   \brief GNU CommonC++ namespace
*/
using namespace ost;

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

};

} /* namespace clamfs */

#endif /* CLAMFS_CONFIG_HXX */

/* EoF */
