/*!\file clamfs.hxx

   \brief ClamFS main file (header file)

*//*

   ClamFS - An user-space anti-virus protected file system
   Copyright (C) 2007-2019 Krzysztof Burghardt

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

#ifndef CLAMFS_CLAMFS_HXX
#define CLAMFS_CLAMFS_HXX

#include "config.h"

#include <Poco/Mutex.h>

#ifdef DMALLOC
   #include <stdlib.h>
   #ifdef HAVE_MALLOC_H
      #include <malloc.h>
   #endif
   #include <dmalloc.h>
#endif

#include "logger.hxx"
#include "config.hxx"
#include "clamav.hxx"
#include "scancache.hxx"
#include "stats.hxx"

/*!\def FUSE_MAX_ARGS
   \brief Maximal value of FUSE arguments counter

   Maximal value for argc (maximal length of argv array)
   we can pass to libFUSE.
*/
#define FUSE_MAX_ARGS 32

namespace clamfs {

using namespace std;
using namespace Poco;

} /* namespace clamfs */

#endif /* CLAMFS_CLAMFS_HXX */

/* EoF */
