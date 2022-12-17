/*!\file stats.hxx

   \brief Statistics (fs, av, cache, etc.) routines (header file)

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2008-2019 Krzysztof Burghardt

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

#include <cstring>
#include <stdlib.h>
#ifdef HAVE_MALLOC_H
   #include <malloc.h>
#endif

#ifdef DMALLOC
   #include <dmalloc.h>
#endif

#include "logger.hxx"

namespace clamfs {

using namespace std;

/*!\class Stats
   \brief Statistics module for ClamFS fs, av, cache and more

   Statistic data collection class with easy to use interface,
   simple analisis and ability to dump statistics to Poco:Logger.
*/
class Stats {
    public:
        /*!\brief Constructor for Stats
           \param dumpEvery time in seconds between stats dump
        */
        Stats(time_t dumpEvery = 0);
        /*!\brief Destructor for Stats */
        ~Stats();

        /*!\brief Enable memory statistics */
        void enableMemoryStats() { memoryStats = true; }

        /*!\brief Dump filesystem statistics to log */
        void dumpFilesystemStatsToLog();

        /*!\brief Dump memory statistics to log */
        void dumpMemoryStatsToLog();

         /*!\brief Periodically dump statistics to log */
        void periodicDumpToLog();

    private:
        /*!\brief Forbid usage of copy constructor */
        Stats(const Stats& aStats);
        /*!\brief Forbid usage of assignment operator */
        Stats& operator = (const Stats& aStats);

        /*!\brief Timestamp of last stats dump */
        time_t lastdump;

        /*!\brief Dump stats every seconds */
        time_t every;

    public:
        /*!\brief early cache hit counter */
        size_t earlyCacheHit;
        /*!\brief early cache miss counter */
        size_t earlyCacheMiss;
        /*!\brief late cache hit counter */
        size_t lateCacheHit;
        /*!\brief late cache miss counter */
        size_t lateCacheMiss;

        /*!\brief whitelist hit counter */
        size_t whitelistHit;
        /*!\brief blacklist hit counter */
        size_t blacklistHit;

        /*!\brief files bigger than maximal-size hit counter */
        size_t tooBigFile;

        /*!\brief open() function call counter */
        size_t openCalled;
        /*!\brief open() call allowed by AV counter */
        size_t openAllowed;
        /*!\brief open() call denied by AV counter */
        size_t openDenied;

        /*!\brief a/v scan failed (clamd unavailable, permission problem, etc.) */
        size_t scanFailed;

        /*!\brief indicates that memory statistics should be included */
        bool memoryStats;
};

/*!\brief extern to access stats pointer from clamfs.cxx */
extern Stats* stats;

/*!\def INC_STAT_COUNTER
   \brief Increment statistic module counter
   \param counter name of counter to increment

   This macro is intended to easier update ClamFS stats module
   counters. This macro check if stats module was initialized
   and if so updates statistic counters.
*/
#define INC_STAT_COUNTER(counter) do {\
    if (stats) {\
        ++(stats->counter);\
    }\
} while(0)


} /* namespace clamfs */

#endif /* CLAMFS_STATS_HXX */

/* EoF */
