/*!\file scancache.hxx

   \brief ScanCache (anti-virus scan result caching) routines (header file)

   $Id: scancache.hxx,v 1.7 2008-11-21 21:16:45 burghardt Exp $

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

#ifndef CLAMFS_SCANCACHE_HXX
#define CLAMFS_SCANCACHE_HXX

#include "config.h"

#include <Poco/ExpireLRUCache.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

namespace clamfs {

using namespace std;
using namespace Poco;

/*!\class ScanCache
   \brief LRU cache for anti-virus scan results storage

   LRU cache with time-based expiration. Based on Poco::ExpireLRUCache.
   This cache stores anti-virus scan results for later use.
*/
class ScanCache: public ExpireLRUCache<ino_t, time_t> {
    public:
        /*!\brief Constructor for ScanCache
           \param elements maximal size of cache
           \param expire maximal TTL for entries
        */
        ScanCache(long int elements, long int expire);
        /*!\brief Destructor for ScanCache */
        ~ScanCache();
    private:
        /*!brief Forbid usage of copy constructor */
        ScanCache(const ScanCache& aCache);
        /*!brief Forbid usage of assignment operator */
        ScanCache& operator = (const ScanCache& aCache);
};

} /* namespace clamfs */

#endif /* CLAMFS_SCANCACHE_HXX */

/* EoF */
