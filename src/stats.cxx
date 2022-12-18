/*!\file stats.cxx

   \brief Statistics (fs, av, cache, etc.) routines

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

    scanFailed = 0;

    memoryStats = false;

    lastdump = time(NULL);
    every = dumpEvery;
}

Stats::~Stats() {
}

void Stats::dumpFilesystemStatsToLog() {
    Logger& logger = Logger::root();
    poco_information(logger, "--- begin of filesystem statistics ---");
    poco_information_f1(logger, "Early cache hit:  %z", earlyCacheHit);
    poco_information_f1(logger, "Early cache miss: %z", earlyCacheMiss);
    poco_information_f1(logger, "Late cache hit:   %z", lateCacheHit);
    poco_information_f1(logger, "Late cache miss:  %z", lateCacheMiss);
    poco_information_f1(logger, "Whitelist hit:    %z", whitelistHit);
    poco_information_f1(logger, "Blacklist hit:    %z", blacklistHit);
    poco_information_f1(logger, "Files bigger than maximal-size: %z", tooBigFile);
    poco_information_f3(logger, "open() function called %z times (allowed: %z, denied: %z)",
            openCalled, openAllowed, openDenied);
    poco_information_f1(logger, "Scan failed %z times", scanFailed);
    poco_information(logger, "--- end of filesystem statistics ---");
}

void Stats::dumpMemoryStatsToLog() {
    Logger& logger = Logger::root();
    poco_information(logger, "--- begin of memory statistics ---");
#if defined(HAVE_MALLINFO2)
    struct mallinfo2 mi = mallinfo2();
    poco_information_f1(logger, "Non-mmapped space allocated (arena):         %z", mi.arena);
    poco_information_f1(logger, "Number of free chunks (ordblks):             %z", mi.ordblks);
    poco_information_f1(logger, "Number of free fastbin blocks (smblks):      %z", mi.smblks);
    poco_information_f1(logger, "Number of mmapped regions (hblks):           %z", mi.hblks);
    poco_information_f1(logger, "Space allocated in mmapped regions (hblkhd): %z", mi.hblkhd);
    poco_information_f1(logger, "Maximum total allocated space (usmblks):     %z", mi.usmblks);
    poco_information_f1(logger, "Space in freed fastbin blocks (fsmblks):     %z", mi.fsmblks);
    poco_information_f1(logger, "Total allocated space (uordblks):            %z", mi.uordblks);
    poco_information_f1(logger, "Total free space (fordblks):                 %z", mi.fordblks);
    poco_information_f1(logger, "Top-most, releasable space (keepcost):       %z", mi.keepcost);
#elif defined(HAVE_MALLINFO)
    struct mallinfo mi = mallinfo();
    poco_information_f1(logger, "Non-mmapped space allocated (arena):         %z", mi.arena);
    poco_information_f1(logger, "Number of free chunks (ordblks):             %z", mi.ordblks);
    poco_information_f1(logger, "Number of free fastbin blocks (smblks):      %z", mi.smblks);
    poco_information_f1(logger, "Number of mmapped regions (hblks):           %z", mi.hblks);
    poco_information_f1(logger, "Space allocated in mmapped regions (hblkhd): %z", mi.hblkhd);
    poco_information_f1(logger, "Maximum total allocated space (usmblks):     %z", mi.usmblks);
    poco_information_f1(logger, "Space in freed fastbin blocks (fsmblks):     %z", mi.fsmblks);
    poco_information_f1(logger, "Total allocated space (uordblks):            %z", mi.uordblks);
    poco_information_f1(logger, "Total free space (fordblks):                 %z", mi.fordblks);
    poco_information_f1(logger, "Top-most, releasable space (keepcost):       %z", mi.keepcost);
#else
    poco_warning(logger, "mallinfo() not available");
#endif
    poco_information(logger, "--- end of memory statistics ---");
}

void Stats::periodicDumpToLog() {
    if (!every)
        return;

    time_t current = time(NULL);
    if ((current - lastdump) > every) {
        dumpFilesystemStatsToLog();
        if (memoryStats)
            dumpMemoryStatsToLog();
        lastdump = current;
    }
}

} /* namespace clamfs */

/* EoF */
