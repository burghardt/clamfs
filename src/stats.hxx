/*!\file stats.hxx

   \brief Statistics (fs, av, cache, etc.) routines (header file)

   $Id: stats.hxx,v 1.1 2008-11-21 21:17:54 burghardt Exp $

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2008 Krzysztof Burghardt.

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

#ifndef CLAMFS_STATS_HXX
#define CLAMFS_STATS_HXX

#include "config.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

namespace clamfs {

using namespace std;

/*!\class Stats
   \brief Statistics module for ClamFS fs, av, cache and more

   Statistic data collection class with easy to use interface,
   simple analisis and ability to dump statistics to rLog.
*/
class Stats {
    public:
        /*!\brief Constructor for Stats
           \param elements maximal size of cache
           \param expire maximal TTL for entries
        */
        Stats();
        /*!\brief Destructor for Stats */
        ~Stats();
    private:
        /*!brief Forbid usage of copy constructor */
        Stats(const Stats& aStats);
        /*!brief Forbid usage of assignment operator */
        Stats& operator = (const Stats& aStats);
};

} /* namespace clamfs */

#endif /* CLAMFS_STATS_HXX */

/* EoF */
