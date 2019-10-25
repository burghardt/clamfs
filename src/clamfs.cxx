/*!\file clamfs.cxx

   \brief ClamFS main file

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

*//*

    Whole code of fusexmp_fh.c has been recopied (mainly for all hooks it contains).
    File fusexmp_fh.c comes with FUSE source code. Original copyright is below.

    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "version.h"
#include "config.h"

#include <iostream>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/file.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <boost/shared_array.hpp>

#include "clamfs.hxx"
#include "utils.hxx"

using namespace std;
using namespace boost;
using namespace clamfs;

/*!\namespace clamfs
   \brief ClamFS own namespace
*/
namespace clamfs {

/*
 * Things needed by all threads (thus global and threads safe)
 */

/*!\brief Saved file descriptor of our base directory */
static int savefd;
/*!\brief Stores all configuration options names and values */
config_t config;
/*!\brief ScanCache instance */
ScanCache *cache = NULL;
/*!\brief Stats instance */
Stats *stats = NULL;
/*!\brief Stores whitelisted and blacklisted file extensions */
extum_t *extensions = NULL;
/*!\brief Mutex need to serialize access to clamd */
FastMutex scanMutex;

extern "C" {

/*!\brief Fixes file path by prefixing it with "." (dot)
   \param path path need to be fixed
   \returns fixed path
*/
static inline const char* fixpath(const char* path)
{
    char* fixed = new char[strlen(path)+2];

    int res = fchdir(savefd);

    if (res < 0)
    {
        char* username = getusername();
        char* callername = getcallername();
        rLog(Warn, "(%s:%d) (%s:%d) %s: fchdir() failed: %s",
                callername, fuse_get_context()->pid, username, fuse_get_context()->uid,
                path, strerror(errno));
        free(username);
        free(callername);
    }

    strcpy(fixed,".");
    strcat(fixed,path);

    return fixed;
}

/*!\brief FUSE getattr() callback
   \param path file path
   \param stbuf buffer to pass to lstat()
   \returns 0 if lstat() returns without error on -errno otherwise
*/
static int clamfs_getattr(const char *path, struct stat *stbuf,
                          struct fuse_file_info *fi)
{
    int res;

    if (fi != NULL)
    {
        res = fstat(fi->fh, stbuf);
    }
    else
    {
       const char* fpath = fixpath(path);
       res = lstat(fpath, stbuf);
       delete[] fpath;
    }
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE access() callback
   \param path file path
   \param mask bit pattern
   \returns 0 if access() returns without error on -errno otherwise
*/
static int clamfs_access(const char *path, int mask)
{
    int res;

    const char* fpath = fixpath(path);
    res = access(fpath, mask);
    delete[] fpath;
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE readlink() callback
   \param path file path
   \param buf data buffer
   \param size buffer size
   \returns 0 if readlink() returns without error on -errno otherwise
*/
static int clamfs_readlink(const char *path, char *buf, size_t size)
{
    ssize_t res;

    const char* fpath = fixpath(path);
    res = readlink(fpath, buf, size - 1);
    delete[] fpath;
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

struct clamfs_dirp {
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

/*!\brief FUSE opendir() callback
   \param path directory path
   \param fi information about open files
   \returns 0 if opendir() returns without error on -errno otherwise
*/
static int clamfs_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;

    const char* fpath = fixpath(path);
    dp = opendir(fpath);
    delete[] fpath;
    if (dp == NULL)
        return -errno;

    fi->fh = (unsigned long) dp;
    return 0;
}

/*!\brief Returns directory pointer from fuse_file_info
   \param fi information about open files
   \returns pointer to file handle
*/
static inline clamfs_dirp *get_dirp(struct fuse_file_info *fi)
{
    return (clamfs_dirp *) (uintptr_t) fi->fh;
}

/*!\brief FUSE readdir() callback
   \param path directory path
   \param buf data buffer
   \param filler directory content filter
   \param offset directory pointer offset
   \param fi information about open files
   \returns always 0
*/
static int clamfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info *fi,
                          enum fuse_readdir_flags flags)
{
    struct clamfs_dirp *d = get_dirp(fi);

    (void) path;
    if (offset != d->offset) {
#ifndef __FreeBSD__
        seekdir(d->dp, offset);
#else
        /* Subtract the one that we add when calling
           telldir() below */
        seekdir(d->dp, offset-1);
#endif
        d->entry = NULL;
        d->offset = offset;
    }
    while (1) {
        struct stat st;
        off_t nextoff;
        int fill_flags = 0;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry)
                break;
        }
#ifdef HAVE_FSTATAT_THAT_WORKS
        if (flags & FUSE_READDIR_PLUS) {
            int res;

            res = fstatat(dirfd(d->dp), d->entry->d_name, &st,
                      AT_SYMLINK_NOFOLLOW);
            if (res != -1)
                fill_flags |= FUSE_FILL_DIR_PLUS;
        }
#else
        (void) flags;
#endif
        if (!(fill_flags & FUSE_FILL_DIR_PLUS)) {
            memset(&st, 0, sizeof(st));
            st.st_ino = d->entry->d_ino;
            st.st_mode = d->entry->d_type << 12;
        }
        nextoff = telldir(d->dp);
#ifdef __FreeBSD__
        /* Under FreeBSD, telldir() may return 0 the first time
           it is called. But for libfuse, an offset of zero
           means that offsets are not supported, so we shift
           everything by one. */
        nextoff++;
#endif
        if (filler(buf, d->entry->d_name, &st, nextoff,
                   (fuse_fill_dir_flags)fill_flags))
            break;

        d->entry = NULL;
        d->offset = nextoff;
    }

    return 0;
}

/*!\brief FUSE releasedir() callback
   \param path directory path
   \param fi information about open files
   \returns always 0
*/
static int clamfs_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct clamfs_dirp *d = get_dirp(fi);
    (void) path;
    closedir(d->dp);
    free(d);
    return 0;
}

/*!\brief FUSE mknod() callback
   \param path file path
   \param mode file permissions
   \param rdev major and minor numbers of device special file
   \returns 0 if mknod() returns without error on -errno otherwise
*/
static int clamfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    const char* fpath = fixpath(path);
    if (S_ISFIFO(mode))
        res = mkfifo(fpath, mode);
    else
        res = mknod(fpath, mode, rdev);
    if (res == -1)
    {
        delete[] fpath;
        return -errno;
    }
    else
    res = lchown(fpath, fuse_get_context()->uid, fuse_get_context()->gid);
    delete[] fpath;

    return 0;
}

/*!\brief FUSE mkdir() callback
   \param path file path
   \param mode file permissions
   \returns 0 if mkdir() returns without error on -errno otherwise
*/
static int clamfs_mkdir(const char *path, mode_t mode)
{
    int res;

    const char* fpath = fixpath(path);
    res = mkdir(fpath, mode);
    if (res == -1)
    {
        delete[] fpath;
        return -errno;
    }
    else
    res = lchown(fpath, fuse_get_context()->uid, fuse_get_context()->gid);
    delete[] fpath;

    return 0;
}

/*!\brief FUSE unlink() callback
   \param path file path
   \returns 0 if unlink() returns without error on -errno otherwise
*/
static int clamfs_unlink(const char *path)
{
    int res;

    const char* fpath = fixpath(path);
    res = unlink(fpath);
    delete[] fpath;
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE rmdir() callback
   \param path directory path
   \returns 0 if rmdir() returns without error on -errno otherwise
*/
static int clamfs_rmdir(const char *path)
{
    int res;

    const char* fpath = fixpath(path);
    res = rmdir(fpath);
    delete[] fpath;
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE symlink() callback
   \param from symlink name
   \param to file path
   \returns 0 if symlink() returns without error on -errno otherwise
*/
static int clamfs_symlink(const char *from, const char *to)
{
    int res;

    const char* fto = fixpath(to);
    res = symlink(from, fto);
    delete[] fto;
    if (res == -1)
        return -errno;
    else
    res = lchown(from, fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

/*!\brief FUSE rename() callback
   \param from old file name
   \param to new file name
   \returns 0 if rename() returns without error on -errno otherwise
*/
static int clamfs_rename(const char *from, const char *to, unsigned int flags)
{
    int res;

    /* When we have renameat2() in libc, then we can implement flags */
    if (flags)
        return -EINVAL;

    const char* ffrom = fixpath(from);
    const char* fto = fixpath(to);
    res = rename(ffrom, fto);
    delete[] ffrom;
    delete[] fto;
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE link() callback
   \param from link name
   \param to file path
   \returns 0 if link() returns without error on -errno otherwise
*/
static int clamfs_link(const char *from, const char *to)
{
    int res;

    const char* ffrom = fixpath(from);
    const char* fto = fixpath(to);
    res = link(ffrom, fto);
    delete[] fto;
    if (res == -1)
    {
        delete[] ffrom;
        return -errno;
    }
    else
        res = lchown(ffrom, fuse_get_context()->uid, fuse_get_context()->gid);
    delete[] ffrom;

    return 0;
}

/*!\brief FUSE chmod() callback
   \param path file path
   \param mode file permissions
   \returns 0 if chmod() returns without error on -errno otherwise
*/
static int clamfs_chmod(const char *path, mode_t mode,
                        struct fuse_file_info *fi)
{
    int res;

    if (fi)
    {
        res = fchmod(fi->fh, mode);
    }
    else
    {
        const char* fpath = fixpath(path);
        res = chmod(fpath, mode);
        delete[] fpath;
    }
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE chown() callback
   \param path file path
   \param uid user id
   \param gid group id
   \returns 0 if chown() returns without error on -errno otherwise
*/
static int clamfs_chown(const char *path, uid_t uid, gid_t gid,
                        struct fuse_file_info *fi)
{
    int res;

    if (fi)
    {
        res = fchown(fi->fh, uid, gid);
    }
    else
    {
        const char* fpath = fixpath(path);
        res = lchown(fpath, uid, gid);
        delete[] fpath;
    }
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE truncate() callback
   \param path file path
   \param size requested size
   \returns 0 if truncate() returns without error on -errno otherwise
*/
static int clamfs_truncate(const char *path, off_t size,
                           struct fuse_file_info *fi)
{
    int res;

    if (fi)
    {
        res = ftruncate(fi->fh, size);
    }
    else
    {
        const char* fpath = fixpath(path);
        res = truncate(fpath, size);
        delete[] fpath;
    }
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
/*!\brief FUSE utimens() callback
   \param path file path
   \returns 0 if utimens() returns without error on -errno otherwise
*/
static int clamfs_utimens(const char *path, const struct timespec ts[2],
                        struct fuse_file_info *fi)
{
    int res;

    /* don't use utime/utimes since they follow symlinks */
    if (fi)
    {
        res = futimens(fi->fh, ts);
    }
    else
    {
        const char* fpath = fixpath(path);
        res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
        delete[] fpath;
    }
    if (res == -1)
        return -errno;

    return 0;
}
#endif

/*!\brief FUSE create() callback
   \param path file path
   \param mode file permissions
   \param fi information about open files
   \returns 0 if open() returns without error on -errno otherwise
*/
static int clamfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int res;
    int fd;

    const char* fpath = fixpath(path);
    fd = open(fpath, fi->flags, mode);
    if (fd == -1)
    {
        delete[] fpath;
        return -errno;
    }
    else
       res = lchown(fpath, fuse_get_context()->uid, fuse_get_context()->gid);
    delete[] fpath;

    if (res < 0)
    {
        char* username = getusername();
        char* callername = getcallername();
        rLog(Warn, "(%s:%d) (%s:%d) %s: lchown() failed: %s",
                callername, fuse_get_context()->pid, username, fuse_get_context()->uid,
                path, strerror(errno));
        free(username);
        free(callername);
    }

    fi->fh = (unsigned long) fd;
    return 0;
}

/*!\brief Opens file and returns it file descriptor by fi->fh
   \param path file path
   \param fi information about open files
   \returns 0 if open() returns without error on -errno otherwise
*/
static inline int open_backend(const char *path, struct fuse_file_info *fi)
{
    int fd;

    const char* fpath = fixpath(path);
    fd = open(fpath, fi->flags);
    delete[] fpath;
    if (fd == -1)
        return -errno;

    fi->fh = (unsigned long) fd;
    return 0;
}

/*!\brief FUSE open() callback
   \param path file path
   \param fi information about open files
   \returns result of open_backend() call or -EPERM if virus is detected
*/
static int clamfs_open(const char *path, struct fuse_file_info *fi)
{
    int ret = 1;
    bool file_is_blacklisted = false;
    int scan_result;
    struct stat file_stat;

    INC_STAT_COUNTER(openCalled);

    /*
     * Dump stats to log periodically
     */
    if (stats) {
        stats->periodicDumpToLog();
    }

    /*
     * Build file path in real filesystem tree
     */
    shared_array<char> real_path(new char[strlen(config["root"])+strlen(path)+1]);
    strcpy(real_path.get(), config["root"]);
    strcat(real_path.get(), path);

    /*
     * Check extension ACL
     */
    if (extensions != NULL) {
        const char *ext = rindex(path, '.'); /* find last dot */
        if (ext != NULL) {
            ++ext; /* omit dot */
            extum_t::const_iterator extumConstIter;
            extumConstIter = extensions->find(ext);
            if (extumConstIter != extensions->end()) {
                switch (extumConstIter->second) {
                    case whitelisted:
                        {
                            INC_STAT_COUNTER(whitelistHit);
                            char* username = getusername();
                            char* callername = getcallername();
                            rLog(Warn, "(%s:%d) (%s:%d) %s: excluded from anti-virus scan because extension whitelisted ",
                                    callername, fuse_get_context()->pid, username, fuse_get_context()->uid, path);
                            free(username);
                            free(callername);
                            INC_STAT_COUNTER(openAllowed);
                            return open_backend(path, fi);
                        }
                    case blacklisted:
                        {
                            INC_STAT_COUNTER(blacklistHit);
                            file_is_blacklisted = true;
                            char* username = getusername();
                            char* callername = getcallername();
                            rLog(Warn, "(%s:%d) (%s:%d) %s: forced anti-virus scan because extension blacklisted ",
                                    callername, fuse_get_context()->pid, username, fuse_get_context()->uid, path);
                            free(username);
                            free(callername);
                            break;
                        }
                    default:
                        DEBUG("Extension found in unordered_map, but with unknown ACL type");
                }
            } else {
                DEBUG("Extension not found in unordered_map");
            }
        }
    }

    /*
     * Check file size (if option defined)
     */
    if ((config["maximal-size"] != NULL) && (file_is_blacklisted == false)) {
        ret = lstat(real_path.get(), &file_stat);
        if (!ret) { /* got file stat without error */
            if (file_stat.st_size > atoi(config["maximal-size"])) { /* file too big */
                INC_STAT_COUNTER(tooBigFile);
                char* username = getusername();
                char* callername = getcallername();
                rLog(Warn, "(%s:%d) (%s:%d) %s: excluded from anti-virus scan because file is too big (file size: %ld bytes)",
                        callername, fuse_get_context()->pid, username, fuse_get_context()->uid, path, (long int)file_stat.st_size);
                free(username);
                free(callername);
                INC_STAT_COUNTER(openAllowed);
                return open_backend(path, fi);
            }
        }
    }

    /*
     * Check if file is in cache
     */
    if (cache != NULL) { /* only if cache initalized */
        if (ret)
            ret = lstat(real_path.get(), &file_stat);
        if (!ret) { /* got file stat without error */

            Poco::SharedPtr<CachedResult> ptr_val;

            if ((ptr_val = cache->get(file_stat.st_ino))) {
                INC_STAT_COUNTER(earlyCacheHit);
                DEBUG("early cache hit for inode %ld", (unsigned long)file_stat.st_ino);

                if (ptr_val->scanTimestamp == file_stat.st_mtime) {
                    INC_STAT_COUNTER(lateCacheHit);
                    DEBUG("late cache hit for inode %ld", (unsigned long)file_stat.st_ino);

                    /* file scanned and not changed, was it clean? */
                    if (ptr_val->isClean) {
                        INC_STAT_COUNTER(openAllowed);
                        return open_backend(path, fi); /* Yes, it was */
                    } else {
                        INC_STAT_COUNTER(openDenied);
                        return -EPERM; /* No, that file was infected */
                    }
                } else {
                    INC_STAT_COUNTER(lateCacheMiss);
                    DEBUG("late cache miss for inode %ld", (unsigned long)file_stat.st_ino);

                    /*
                     * Scan file when file it was changed
                     */
                    scan_result = ClamavScanFile(real_path.get());

                    /*
                     * Check for scan results and update cache
                     */
                    ptr_val->scanTimestamp = file_stat.st_mtime;
                    if (scan_result == 1) { /* virus found */
                        ptr_val->isClean = false;
                        INC_STAT_COUNTER(openDenied);
                        return -EPERM;
                    } else if(scan_result == 0) {
                        ptr_val->isClean = true;
                        INC_STAT_COUNTER(openAllowed);
                        /* file is clean, open it */
                        return open_backend(path, fi);
                    } else {
                        INC_STAT_COUNTER(scanFailed);
                        INC_STAT_COUNTER(openDenied);
                        cache->remove(file_stat.st_ino);
                        return -EPERM;
                    }
                }

            } else {
                INC_STAT_COUNTER(earlyCacheMiss);
                DEBUG("early cache miss for inode %ld", (unsigned long)file_stat.st_ino);

                /*
                 * Scan file when file is not in cache
                 */
                scan_result = ClamavScanFile(real_path.get());

                /*
                 * Check for scan results
                 */
                if (scan_result == 1) { /* virus found */
                    CachedResult result(false, file_stat.st_mtime);
                    cache->add(file_stat.st_ino, result);
                    INC_STAT_COUNTER(openDenied);
                    return -EPERM;
                } else if(scan_result == 0) {
                    CachedResult result(true, file_stat.st_mtime);
                    cache->add(file_stat.st_ino, result);
                    INC_STAT_COUNTER(openAllowed);
                    /* file is clean, open it */
                    return open_backend(path, fi);
                } else {
                    INC_STAT_COUNTER(scanFailed);
                    INC_STAT_COUNTER(openDenied);
                    cache->remove(file_stat.st_ino);
                    return -EPERM;
                }

            }

        }
    }

    /*
     * Scan file when cache is not available
     */
    scan_result = ClamavScanFile(real_path.get());

    /*
     * Check for scan results
     */
    if (scan_result == 1) { /* return -EPERM error if virus was found */
        INC_STAT_COUNTER(openDenied);
        return -EPERM;
    } else if(scan_result != 0) {
        INC_STAT_COUNTER(scanFailed);
        INC_STAT_COUNTER(openDenied);
        return -EPERM;
    }

    /*
     * If no virus detected continue as usual
     */
    INC_STAT_COUNTER(openAllowed);
    return open_backend(path, fi);
}

/*!\brief FUSE read() callback
   \param path file path
   \param buf data buffer
   \param size buffer size
   \param offset read offset
   \param fi information about open files
   \returns 0 if pread() returns without error on -errno otherwise
*/
static int clamfs_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    ssize_t res;

    (void) path;
    res = pread((int)fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return (int)res;
}

static int clamfs_read_buf(const char *path, struct fuse_bufvec **bufp,
                        size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct fuse_bufvec *src;

    (void) path;

    src = (fuse_bufvec*)malloc(sizeof(struct fuse_bufvec));
    if (src == NULL)
        return -ENOMEM;

    *src = FUSE_BUFVEC_INIT(size);

    src->buf[0].flags = (fuse_buf_flags)(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
    src->buf[0].fd = fi->fh;
    src->buf[0].pos = offset;

    *bufp = src;

    return 0;
}

/*!\brief FUSE write() callback
   \param path file path
   \param buf data buffer
   \param size buffer size
   \param offset read offset
   \param fi information about open files
   \returns 0 if pwrite() returns without error on -errno otherwise
*/
static int clamfs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    ssize_t res;

    (void) path;
    res = pwrite((int)fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return (int)res;
}

static int clamfs_write_buf(const char *path, struct fuse_bufvec *buf,
                         off_t offset, struct fuse_file_info *fi)
{
    struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

    (void) path;

    dst.buf[0].flags = (fuse_buf_flags)(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
    dst.buf[0].fd = fi->fh;
    dst.buf[0].pos = offset;

    return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

/*!\brief FUSE statfs() callback
   \param path file path
   \param stbuf data buffer
   \returns 0 if statvfs() returns without error on -errno otherwise
*/
static int clamfs_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    const char* fpath = fixpath(path);
    res = statvfs(fpath, stbuf);
    delete[] fpath;
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_flush(const char *path, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    /* This is called from every close on an open file, so call the
       close on the underlying filesystem.  But since flush may be
       called multiple times for an open file, this must not really
       close the file.  This is important if used on a network
       filesystem like NFS which flush the data/metadata on close() */
    res = close(dup(fi->fh));
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE release() callback
   \param path file path
   \param fi information about open files
   \returns always 0
*/
static int clamfs_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    close((int)fi->fh);

    return 0;
}

/*!\brief FUSE fsync() callback
   \param path file path
   \param isdatasync data sync flag
   \param fi information about open files
   \returns 0 if f{data}sync() returns without error on -errno otherwise
*/
static int clamfs_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    int res;
    (void) path;

#ifndef HAVE_FDATASYNC
    (void) isdatasync;
#else
    if (isdatasync)
        res = fdatasync((int)fi->fh);
    else
#endif
        res = fsync((int)fi->fh);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_SETXATTR
/*!\brief FUSE setxattr() callback
   \param path file path
   \param name extended attribute name
   \param value extended attribute value
   \param size size of value
   \param flags operation options
   \returns 0 if lsetxattr() returns without error on -errno otherwise
*/
static int clamfs_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
    int res;
    const char* fpath = fixpath(path);
    res = lsetxattr(fpath, name, value, size, flags);
    delete[] fpath;
    if (res == -1)
        return -errno;
    return 0;
}

/*!\brief FUSE getxattr() callback
   \param path file path
   \param name extended attribute name
   \param value extended attribute value
   \param size size of value
   \returns 0 if lgetxattr() returns without error on -errno otherwise
*/
static int clamfs_getxattr(const char *path, const char *name, char *value,
                    size_t size)
{
    ssize_t res;
    const char* fpath = fixpath(path);
    res = lgetxattr(fpath, name, value, size);
    delete[] fpath;
    if (res == -1)
        return -errno;
    return (int)res;
}

/*!\brief FUSE listxattr() callback
   \param path file path
   \param list list of extended attribute names
   \param size size of list
   \returns 0 if llistxattr() returns without error on -errno otherwise
*/
static int clamfs_listxattr(const char *path, char *list, size_t size)
{
    ssize_t res;
    const char* fpath = fixpath(path);
    res = llistxattr(fpath, list, size);
    delete[] fpath;
    if (res == -1)
        return -errno;
    return (int)res;
}

/*!\brief FUSE removexattr() callback
   \param path file path
   \param name extended attribute name
   \returns 0 if lremovexattr() returns without error on -errno otherwise
*/
static int clamfs_removexattr(const char *path, const char *name)
{
    int res;
    const char* fpath = fixpath(path);
    res = lremovexattr(fpath, name);
    delete[] fpath;
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

/*!\brief ClamFS main()
   \param argc arguments counter
   \param argv arguments array
   \returns 0 on success, error code otherwise
*/
int main(int argc, char *argv[]);
int main(int argc, char *argv[])
{
    int ret;
    int fuse_argc;
    char **fuse_argv;
    fuse_operations clamfs_oper;

    /*
     * Make sure all pointers are initialy set to NULL
     */
    memset(&clamfs_oper, 0, sizeof(fuse_operations));

    clamfs_oper.getattr     = clamfs_getattr;
    clamfs_oper.access      = clamfs_access;
    clamfs_oper.readlink    = clamfs_readlink;
    clamfs_oper.opendir     = clamfs_opendir;
    clamfs_oper.readdir     = clamfs_readdir;
    clamfs_oper.releasedir  = clamfs_releasedir;
    clamfs_oper.mknod       = clamfs_mknod;
    clamfs_oper.mkdir       = clamfs_mkdir;
    clamfs_oper.symlink     = clamfs_symlink;
    clamfs_oper.unlink      = clamfs_unlink;
    clamfs_oper.rmdir       = clamfs_rmdir;
    clamfs_oper.rename      = clamfs_rename;
    clamfs_oper.link        = clamfs_link;
    clamfs_oper.chmod       = clamfs_chmod;
    clamfs_oper.chown       = clamfs_chown;
    clamfs_oper.truncate    = clamfs_truncate;
#ifdef HAVE_UTIMENSAT
    clamfs_oper.utimens     = clamfs_utimens;
#endif
    clamfs_oper.create      = clamfs_create;
    clamfs_oper.open        = clamfs_open;
    clamfs_oper.read        = clamfs_read;
    clamfs_oper.read_buf    = clamfs_read_buf;
    clamfs_oper.write       = clamfs_write;
    clamfs_oper.write_buf   = clamfs_write_buf;
    clamfs_oper.statfs      = clamfs_statfs;
    clamfs_oper.flush       = clamfs_flush;
    clamfs_oper.release     = clamfs_release;
    clamfs_oper.fsync       = clamfs_fsync;
#ifdef HAVE_SETXATTR
    clamfs_oper.setxattr    = clamfs_setxattr;
    clamfs_oper.getxattr    = clamfs_getxattr;
    clamfs_oper.listxattr   = clamfs_listxattr;
    clamfs_oper.removexattr = clamfs_removexattr;
#endif

    umask(0);

    /*
     * Open RLog
     */
    RLogInit(argc, argv);
    RLogOpenStdio();

    rLog(Info, "ClamFS v" VERSION " (git-" PACKAGE_VERSION_GIT_DESCRIBE ")");
    rLog(Info, "Copyright (c) 2007-2019 Krzysztof Burghardt <krzysztof@burghardt.pl>");
    rLog(Info, "https://github.com/burghardt/clamfs");

    /*
     * Check if we have one argument (other arguments are assumed RLog related)
     */
    if ((argc < 2) ||
        ((argc > 1) &&
         ((strncmp(argv[1], "-h", strlen("-h")) == 0) ||
          (strncmp(argv[1], "--help", strlen("--help")) == 0)))) {
        rLog(Warn, "ClamFS need to be invoked with one parameter - location of configuration file");
        rLog(Warn, "Example: %s /etc/clamfs/home.xml", argv[0]);
        return EXIT_FAILURE;
    }

    /*
     * Load XML configuration file, parse it and fill in clamfs::config
     */
    ConfigParserXML cp(argv[1]);
    if (config.size() == 0) {
        rLog(Warn, "No configuration has been loaded");
        return EXIT_FAILURE;
    }

#ifndef NDEBUG
    /*
     * Dump configuration form clamfs::config
     */
    cout << "--- begin of config dump ---" << endl;
    config_t::iterator m_begin = config.begin();
    config_t::iterator m_end   = config.end();
    while (m_begin != m_end) {
        cout << (*m_begin).first << ": " << (*m_begin).second << endl;
        ++m_begin;
    }
    cout << "--- end of config dump ---" << endl;
#endif

    /*
     * Check if minimal set of configuration options has been defined
     * (any other option can be omitted but this three are mandatory)
     */
    if ((config["socket"] == NULL) ||
        (config["root"] == NULL) ||
        (config["mountpoint"] == NULL)) {
        rLog(Warn, "socket, root and mountpoint must be defined");
        return EXIT_FAILURE;
    }

    /*
     * Build argv for libFUSE
     */
    fuse_argv = new char *[FUSE_MAX_ARGS];
    memset(fuse_argv, 0, FUSE_MAX_ARGS * sizeof(char *)); /* set pointers to NULL */
    fuse_argc = 0;
    fuse_argv[fuse_argc++] = strdup(argv[0]); /* copy program name */
    fuse_argv[fuse_argc++] = strdup(config["mountpoint"]); /* set mountpoint */

    if ((config["public"] != NULL) && /* public */
        (strncmp(config["public"], "yes", 3) == 0)) {
        fuse_argv[fuse_argc++] = strdup("-o");
        if ((config["nonempty"] != NULL) && /* public and nonempty */
            (strncmp(config["nonempty"], "yes", 3) == 0)) {
#ifdef HAVE_SETXATTR_WITH_ACL_PATCH
            fuse_argv[fuse_argc++] =
                strdup("allow_other,default_permissions,acl,nonempty");
#else
            fuse_argv[fuse_argc++] =
                strdup("allow_other,default_permissions,nonempty");
#endif
        } else { /* public without nonempty */
#ifdef HAVE_SETXATTR_WITH_ACL_PATCH
            fuse_argv[fuse_argc++] = strdup("allow_other,default_permissions,acl");
#else
            fuse_argv[fuse_argc++] = strdup("allow_other,default_permissions");
#endif
        }
    } else if ((config["nonempty"] != NULL) && /* private and nonempty */
        (strncmp(config["nonempty"], "yes", 3) == 0)) {
        fuse_argv[fuse_argc++] = strdup("-o");
#ifdef HAVE_SETXATTR_WITH_ACL_PATCH
        fuse_argv[fuse_argc++] = strdup("nonempty,default_permissions,acl");
#else
        fuse_argv[fuse_argc++] = strdup("nonempty");
#endif
#ifdef HAVE_SETXATTR_WITH_ACL_PATCH
    } else {
        fuse_argv[fuse_argc++] = strdup("-o");
        fuse_argv[fuse_argc++] = strdup("default_permissions,acl");
#endif
    }

    if ((config["readonly"] != NULL) &&
        (strncmp(config["readonly"], "yes", 3) == 0))
        fuse_argv[fuse_argc++] = strdup("-r");

    if ((config["threads"] != NULL) &&
        (strncmp(config["threads"], "no", 2) == 0))
        fuse_argv[fuse_argc++] = strdup("-s");

    if ((config["fork"] != NULL) &&
        (strncmp(config["fork"], "no", 2) == 0))
        fuse_argv[fuse_argc++] = strdup("-f");

    /*
     * Change our current directory to "root" of our filesystem
     */
    rLog(Info,"chdir to our 'root' (%s)",config["root"]);
    if (chdir(config["root"]) < 0) {
        int err = errno; /* copy errno, RLog can overwrite */
        rLog(Warn, "chdir failed: %s", strerror(err));
        return err;
    }
    savefd = open(".", 0);

    /*
     * Check if clamd is available for clamfs only if check option is not "no"
     */
    if ((config["check"] == NULL) ||
        (strncmp(config["check"], "no", 2) != 0)) {
        if ((ret = OpenClamav(config["socket"])) != 0) {
            rLog(Warn, "cannot start without running clamd, make sure it works");
            return ret;
        }

        if ((ret = PingClamav()) != 0) {
            rLog(Warn, "cannot start without running clamd, make sure it works");
            return ret;
        }
        CloseClamav();
    }

    /*
     * Initialize cache
     */
    if ((config["entries"] != NULL) &&
        (atol(config["entries"]) <= 0)) {
        rLog(Warn, "maximal cache entries count cannot be =< 0");
        return EXIT_FAILURE;
    }
    if ((config["expire"] != NULL) &&
        (atol(config["expire"]) <= 0)) {
        rLog(Warn, "maximal cache expire value cannot be =< 0");
        return EXIT_FAILURE;
    }
    if ((config["entries"] != NULL) &&
        (config["expire"] != NULL)) {
        rLog(Info, "ScanCache initialized, %s entries will be kept for %s ms max.",
            config["entries"], config["expire"]);
        cache = new ScanCache(atol(config["entries"]), atol(config["expire"]));
    } else {
        rLog(Warn, "ScanCache disabled, expect poor performance");
    }

    /*
     * Initialize stats
     */
    if ((config["every"] != NULL) &&
        (atol(config["every"]) != 0)) {
        rLog(Info, "Statistics module initialized");
        stats = new Stats(atol(config["every"]));
    } else if ((config["atexit"] != NULL) &&
        (strncmp(config["atexit"], "yes", 3) == 0)) {
        rLog(Info, "Statistics module initialized");
        stats = new Stats(0);
    } else {
        rLog(Info, "Statistics module disabled");
    }

    if ((config["memory"] != NULL) &&
        (strncmp(config["memory"], "yes", 3) == 0)) {
        stats->enableMemoryStats();
    }

    /*
     * Open configured logging target
     */
    if (config["method"] != NULL) {
        if (strncmp(config["method"], "syslog", 6) == 0) {
            RLogOpenSyslog();
            RLogCloseStdio();
        } else if (strncmp(config["method"], "file", 4) == 0) {
            if (config["filename"] != NULL) {
                RLogOpenLogFile(config["filename"]);
                RLogCloseStdio();
            } else {
                rLog(Warn, "logging method 'file' chosen, but no log 'filename' given");
                return EXIT_FAILURE;
            }
        }
    }

    /*
     * Print size of extensions ACL
     */
    if (extensions != NULL) {
        rLog(Info, "extension ACL size is %d entries", (int)extensions->size());
    }

    /*
     * Start FUSE
     */
    ret = fuse_main(fuse_argc, fuse_argv, &clamfs_oper, NULL);

    for (unsigned int i = 0; i < FUSE_MAX_ARGS; ++i)
        if (fuse_argv[i])
            free(fuse_argv[i]);
    delete[] fuse_argv;

    if (cache) {
        rLog(Info, "deleting cache");
        delete cache;
        cache = NULL;
    }

    if (stats) {
        if ((config["atexit"] != NULL) &&
            (strncmp(config["atexit"], "yes", 3) == 0)) {
            stats->dumpFilesystemStatsToLog();
            if (stats->memoryStats)
                stats->dumpMemoryStatsToLog();
        }

        rLog(Info, "deleting stats");
        delete stats;
        stats = NULL;
    }

    if (extensions != NULL) {
        rLog(Info, "deleting extensions ACL");
        delete extensions;
        extensions = NULL;
    }

    rLog(Info, "closing logging targets");
    RLogCloseLogFile();

    rLog(Warn,"exiting");
#ifdef DMALLOC
    dmalloc_verify(0L);
#endif
    return ret;
}

} /* extern "C" */

} /* namespace clamfs */

/* EoF */
