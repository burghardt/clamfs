/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: scancache.hxx,v 1.2 2007-02-07 15:39:29 burghardt Exp $

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

#include <config.h>

#include <Poco/ExpireLRUCache.h>

namespace clamfs {

using namespace std;
using namespace Poco;

class ScanCache: public ExpireLRUCache<ino_t, time_t> {
    public:
    	ScanCache(int elements, int expire);
};

} /* namespace clamfs */

#endif /* CLAMFS_SCANCACHE_HXX */

/* EoF */
