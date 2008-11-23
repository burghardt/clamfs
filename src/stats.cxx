/*!\file stats.cxx

   \brief Statistics (fs, av, cache, etc.) routines

   $Id: stats.cxx,v 1.4 2008-11-23 16:04:24 burghardt Exp $

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

#include "stats.hxx"

namespace clamfs {

Stats::Stats(time_t dumpEvery) {
    earlyCacheHit = 0;
    earlyCacheMiss = 0;
    lateCacheHit = 0;
    lateCacheMiss = 0;

    whitelistHit = 0;
    blacklistHit = 0;

    tooBigFile = 0;

    openCalled = 0;
    openAllowed = 0;
    openDenied = 0;

    lastdump = time(NULL);
    every = dumpEvery;
}

Stats::~Stats() {
}

void Stats::dumpToLog() {
    rLog(Info, "--- begin of statistics ---");
    rLog(Info, "Early cache hit: %llu", earlyCacheHit);
    rLog(Info, "Early cache miss: %llu", earlyCacheMiss);
    rLog(Info, "Late cache hit: %llu", lateCacheHit);
    rLog(Info, "Late cache miss: %llu", lateCacheMiss);
    rLog(Info, "Whitelist hit: %llu", whitelistHit);
    rLog(Info, "Blacklist hit: %llu", blacklistHit);
    rLog(Info, "Files bigger than maximal-size: %llu", tooBigFile);
    rLog(Info, "open() function called %llu times (allowed: %llu, denied: %llu)",
            openCalled, openAllowed, openDenied);
    rLog(Info, "--- end of statistics ---");
}

void Stats::periodicDumpToLog() {
    if (!every)
        return;

    time_t current = time(NULL);
    if ((current - lastdump) > every) {
        dumpToLog();
        lastdump = current;
    }
}

} /* namespace clamfs */

/* EoF */
