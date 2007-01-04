/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2006 Krzysztof Burghardt.

   $Id: clamfs.cxx,v 1.1.1.1 2007-01-04 02:22:47 burghardt Exp $

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

/*
    Whole code of fusexmp_fh.c has been recopied (mainly for all hooks it contains).
    File fusexmp_fh.c comes with FUSE source code. Original copyright is below.

    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <config.h>

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <clamfs.hxx>

using namespace clamfs;

static int clamfs_getattr(const char *path, struct stat *stbuf)
{
    int res;

    res = lstat(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_fgetattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
    int res;

    (void) path;

    res = fstat(fi->fh, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_access(const char *path, int mask)
{
    int res;

    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_readlink(const char *path, char *buf, size_t size)
{
    int res;

    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

static int clamfs_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp = opendir(path);
    if (dp == NULL)
        return -errno;

    fi->fh = (unsigned long) dp;
    return 0;
}

static inline DIR *get_dirp(struct fuse_file_info *fi)
{
    return (DIR *) (uintptr_t) fi->fh;
}

static int clamfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR *dp = get_dirp(fi);
    struct dirent *de;

    (void) path;
    seekdir(dp, offset);
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, telldir(dp)))
            break;
    }

    return 0;
}

static int clamfs_releasedir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp = get_dirp(fi);
    (void) path;
    closedir(dp);
    return 0;
}

static int clamfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_mkdir(const char *path, mode_t mode)
{
    int res;

    res = mkdir(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_unlink(const char *path)
{
    int res;

    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_rmdir(const char *path)
{
    int res;

    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_symlink(const char *from, const char *to)
{
    int res;

    res = symlink(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_rename(const char *from, const char *to)
{
    int res;

    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_chmod(const char *path, mode_t mode)
{
    int res;

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_truncate(const char *path, off_t size)
{
    int res;

    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_ftruncate(const char *path, off_t size,
                         struct fuse_file_info *fi)
{
    int res;

    (void) path;

    res = ftruncate(fi->fh, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_utime(const char *path, struct utimbuf *buf)
{
    int res;

    res = utime(path, buf);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;

    fd = open(path, fi->flags, mode);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int clamfs_open(const char *path, struct fuse_file_info *fi)
{
    int fd;

    if (ClamavScanFile(path) != 0) {
	return -EPERM;
    }

    fd = open(path, fi->flags);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int clamfs_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int clamfs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int clamfs_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    res = statvfs(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    close(fi->fh);

    return 0;
}

static int clamfs_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    int res;
    (void) path;

#ifndef HAVE_FDATASYNC
    (void) isdatasync;
#else
    if (isdatasync)
        res = fdatasync(fi->fh);
    else
#endif
        res = fsync(fi->fh);
    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int clamfs_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
    int res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int clamfs_getxattr(const char *path, const char *name, char *value,
                    size_t size)
{
    int res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int clamfs_listxattr(const char *path, char *list, size_t size)
{
    int res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int clamfs_removexattr(const char *path, const char *name)
{
    int res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

int main(int argc, char *argv[])
{
    int ret;
    fuse_operations clamfs_oper;

    // Make sure all pointers are initialy set to NULL
    memset(&clamfs_oper, 0, sizeof(fuse_operations));

    clamfs_oper.getattr		= clamfs_getattr;
    clamfs_oper.fgetattr	= clamfs_fgetattr;
    clamfs_oper.access		= clamfs_access;
    clamfs_oper.readlink	= clamfs_readlink;
    clamfs_oper.opendir		= clamfs_opendir;
    clamfs_oper.readdir		= clamfs_readdir;
    clamfs_oper.releasedir	= clamfs_releasedir;
    clamfs_oper.mknod		= clamfs_mknod;
    clamfs_oper.mkdir		= clamfs_mkdir;
    clamfs_oper.symlink		= clamfs_symlink;
    clamfs_oper.unlink		= clamfs_unlink;
    clamfs_oper.rmdir		= clamfs_rmdir;
    clamfs_oper.rename		= clamfs_rename;
    clamfs_oper.link		= clamfs_link;
    clamfs_oper.chmod		= clamfs_chmod;
    clamfs_oper.chown		= clamfs_chown;
    clamfs_oper.truncate	= clamfs_truncate;
    clamfs_oper.ftruncate	= clamfs_ftruncate;
    clamfs_oper.utime		= clamfs_utime;
    clamfs_oper.create		= clamfs_create;
    clamfs_oper.open		= clamfs_open;
    clamfs_oper.read		= clamfs_read;
    clamfs_oper.write		= clamfs_write;
    clamfs_oper.statfs		= clamfs_statfs;
    clamfs_oper.release		= clamfs_release;
    clamfs_oper.fsync		= clamfs_fsync;
#ifdef HAVE_SETXATTR
    clamfs_oper.setxattr	= clamfs_setxattr;
    clamfs_oper.getxattr	= clamfs_getxattr;
    clamfs_oper.listxattr	= clamfs_listxattr;
    clamfs_oper.removexattr	= clamfs_removexattr;
#endif

    umask(0);
    
    RLogInit(argc, argv);
    RLogOpenStdio();

    rLog(Info, "ClamFS v"VERSION);
    rLog(Info, "Copyright (c) 2006 Krzysztof Burghardt <krzysztof@burghardt.pl>");
    rLog(Info, "http://clamfs.sourceforge.net/");

    ConfigParserXML cp("../doc/clamfs.xml");

    if ((ret = OpenClamav("/var/run/clamav/clamd.ctl")) != 0) {
	rLog(Warn, "cannot start without running clamd, make sure it works");
	return ret;
    }

    if ((ret = PingClamav()) != 0) {
	rLog(Warn, "cannot start without running clamd, make sure it works");
	return ret;
    }
    
    CloseClamav();

    RLogOpenSyslog();
    RLogCloseStdio();

//    ret = fuse_main(argc, argv, &clamfs_oper);
    
    rLog(Warn,"exiting");
    
    return ret;
}

// EoF
