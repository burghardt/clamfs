/*!\file utils.hxx

   \brief Misc routines (header file)

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

#ifndef CLAMFS_UTILS_HXX
#define CLAMFS_UTILS_HXX

#include "config.h"

#include <cstring>
#include <stdlib.h>
#include <fuse.h>
#include <pwd.h>

#ifdef DMALLOC
   #ifdef HAVE_MALLOC_H
      #include <malloc.h>
   #endif
   #include <dmalloc.h>
#endif

namespace clamfs {

/*!\struct ltstr
   \brief Comparison function for clamfs::config

   A Strict Weak Ordering comparison function.
   It is a Binary Predicate that compares two objects,
   returning true if the first precedes the second.
*/
struct ltstr {
    bool operator()(const char *s1, const char *s2) const {
        return strcmp(s1, s2) < 0;
    }
};

/*!\brief Returns the name of the process which accessed the file system
   \returns pointer to buffer contains process name
*//*

    This function was written by Remi Flament <rflament at laposte dot net>
    Copyright (c) 2005 - 2007, Remi Flament
    License: GNU GPL

*/
static inline char* getcallername() {
    char* filename = NULL;
    char* res = NULL;
    if (asprintf(&filename, "/proc/%d/cmdline", fuse_get_context()->pid) > 0) {
        FILE* proc=fopen(filename, "rt");
        if (proc != NULL) {
            free(filename);
            char cmdline[256];
            memset(cmdline, 0, sizeof(cmdline));
            size_t read = fread(cmdline, sizeof(cmdline) - 1, 1, proc);
            if (1 == read) {
                res = strdup(cmdline);
            } else {
                if (feof(proc))
                    res = strdup(cmdline);
            }
            fclose(proc);
       }
    }
    if (res == NULL)
        res = strdup("< unknown >");
    return res;
}

/*!\brief Returns the name of the user accessed the filesystem
   \returns pointer to buffer contains user name */
static inline char* getusername() {
    struct passwd* s_pwd;
    s_pwd = getpwuid(fuse_get_context()->uid);
    return strdup(s_pwd->pw_name);
}

} /* namespace clamfs */

#endif /* CLAMFS_UTILS_HXX */

/* EoF */
