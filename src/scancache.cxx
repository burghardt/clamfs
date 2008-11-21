/*!\file scancache.cxx

   \brief ScanCache (anti-virus scan result caching) routines

   $Id: scancache.cxx,v 1.6 2008-11-21 23:58:11 burghardt Exp $

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

#include "scancache.hxx"

namespace clamfs {

CachedResult::CachedResult(bool isFileClean, time_t scanFileTimestamp) {
    isClean = isFileClean;
    scanTimestamp = scanFileTimestamp;
}

CachedResult::~CachedResult() {
}

ScanCache::ScanCache(long int elements, long int expire):
    ExpireLRUCache<ino_t, CachedResult>::ExpireLRUCache<ino_t, CachedResult>(elements, expire) {
}

ScanCache::~ScanCache() {
}

} /* namespace clamfs */

/* EoF */
