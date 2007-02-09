/*
   ClamFS - Userspace anti-virus secured filesystem
   Copyright (C) 2007 Krzysztof Burghardt.

   $Id: clamfs.cxx,v 1.5 2007-02-09 21:21:21 burghardt Exp $

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
#include <utils.hxx>

using namespace clamfs;

namespace clamfs {

static int savefd;
map <const char *, char *, ltstr> config;

ScanCache *cache = NULL;

FastMutex scanMutex;

}

extern "C" {

static char* clamfs_fixpath(const char* path)
{
    char* fixed=new char[strlen(path)+2];
    
    fchdir(savefd);
    strcpy(fixed,".");
    strcat(fixed,path);
    
    return fixed;
}

static int clamfs_getattr(const char *path, struct stat *stbuf)
{
    int res;

    path = clamfs_fixpath(path);
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

    path = clamfs_fixpath(path);
    res = access(path, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_readlink(const char *path, char *buf, size_t size)
{
    int res;

    path = clamfs_fixpath(path);
    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

static int clamfs_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;

    path = clamfs_fixpath(path);
    dp = opendir(path);
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

    path = clamfs_fixpath(path);
    if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    if (res == -1)
        return -errno;
    else
	res = lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

static int clamfs_mkdir(const char *path, mode_t mode)
{
    int res;

    path = clamfs_fixpath(path);
    res = mkdir(path, mode);
    if (res == -1)
        return -errno;
    else
	res = lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

static int clamfs_unlink(const char *path)
{
    int res;

    path = clamfs_fixpath(path);
    res = unlink(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_rmdir(const char *path)
{
    int res;

    path = clamfs_fixpath(path);
    res = rmdir(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_symlink(const char *from, const char *to)
{
    int res;

    from = clamfs_fixpath(from);
    to = clamfs_fixpath(to);
    res = symlink(from, to);
    if (res == -1)
        return -errno;
    else
	res = lchown(from, fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

static int clamfs_rename(const char *from, const char *to)
{
    int res;

    from = clamfs_fixpath(from);
    to = clamfs_fixpath(to);
    res = rename(from, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_link(const char *from, const char *to)
{
    int res;

    from = clamfs_fixpath(from);
    to = clamfs_fixpath(to);
    res = link(from, to);
    if (res == -1)
        return -errno;
    else
	res = lchown(from, fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

static int clamfs_chmod(const char *path, mode_t mode)
{
    int res;

    path = clamfs_fixpath(path);
    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    path = clamfs_fixpath(path);
    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_truncate(const char *path, off_t size)
{
    int res;

    path = clamfs_fixpath(path);
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

    path = clamfs_fixpath(path);
    res = utime(path, buf);
    if (res == -1)
        return -errno;

    return 0;
}

static int clamfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int res;
    int fd;

    path = clamfs_fixpath(path);
    fd = open(path, fi->flags, mode);
    if (fd == -1)
        return -errno;
    else
	res = lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);

    fi->fh = fd;
    return 0;
}

static inline int clamfs_open_backend(const char *path, struct fuse_file_info *fi)
{
    int fd;

    path = clamfs_fixpath(path);
    fd = open(path, fi->flags);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int clamfs_open(const char *path, struct fuse_file_info *fi)
{
    int ret;
    int scan_result;
    struct stat file_stat;

    /*
     * Build file path in real filesystem tree
     */
    char *real_path = new char[strlen(config["root"])+strlen(path)+1];
    strcpy(real_path, config["root"]);
    strcat(real_path, path);

    /*
     * Check if file is in cache
     */
    if (cache != NULL) { /* only if cache initalized */
	ret = lstat(real_path, &file_stat);
	if (!ret) { /* got file stat without error */
	
	    if (cache->has(file_stat.st_ino)) {
		Poco::SharedPtr<time_t> ptr_val;
		DEBUG("early cache hit for inode %ld", (unsigned long)file_stat.st_ino);
		ptr_val = cache->get(file_stat.st_ino);
		
		if (*ptr_val == file_stat.st_mtime) {
		    DEBUG("late cache hit for inode %ld", (unsigned long)file_stat.st_ino);
		    
		    /* file scanned and not changed, just open it */
		    return clamfs_open_backend(path, fi);
		} else {
		    DEBUG("late cache miss for inode %ld", (unsigned long)file_stat.st_ino);

		    /*
		     * Scan file when file it was changed
		     */
		    scan_result = ClamavScanFile(real_path);
	    	    delete real_path;
		    real_path = NULL;

	    	    /*
	             * Check for scan results
	    	     */
	    	    if (scan_result != 0) { /* delete from cache and return -EPERM error if virus was found */
			cache->remove(file_stat.st_ino);
			return -EPERM;
		    }
		
		    /* file was clean so update cache */
		    *ptr_val = file_stat.st_mtime;

		    /* and open it */
		    return clamfs_open_backend(path, fi);
		}

	    } else {
		DEBUG("cache miss for inode %ld", (unsigned long)file_stat.st_ino);
		
	        /*
	         * Scan file when file is not in cache
	         */
	        scan_result = ClamavScanFile(real_path);
	        delete real_path;
		real_path = NULL;

	        /*
	         * Check for scan results
	         */
	        if (scan_result != 0) /* return -EPERM error if virus was found */
		    return -EPERM;
		
		/* file was clean so add it to cache */
		cache->add(file_stat.st_ino, file_stat.st_mtime);

		/* and open it */
		return clamfs_open_backend(path, fi);
		
	    }
	
	}
    }

    /*
     * Scan file when cache is not available
     */
    scan_result = ClamavScanFile(real_path);
    delete real_path;
    real_path = NULL;

    /*
     * Check for scan results
     */
    if (scan_result != 0) /* return -EPERM error if virus was found */
	return -EPERM;

    /*
     * If no virus detected continue as usual
     */
    return clamfs_open_backend(path, fi);
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

    path = clamfs_fixpath(path);
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
    int res;
    path = clamfs_fixpath(path);
    res = lsetxattr(path, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int clamfs_getxattr(const char *path, const char *name, char *value,
                    size_t size)
{
    int res;
    path = clamfs_fixpath(path);
    res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int clamfs_listxattr(const char *path, char *list, size_t size)
{
    int res;
    path = clamfs_fixpath(path);
    res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int clamfs_removexattr(const char *path, const char *name)
{
    int res;
    path = clamfs_fixpath(path);
    res = lremovexattr(path, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

} /* extern "C" */

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

    /*
     * Open rLog
     */    
    RLogInit(argc, argv);
    RLogOpenStdio();

    rLog(Info, "ClamFS v"VERSION);
    rLog(Info, "Copyright (c) 2007 Krzysztof Burghardt <krzysztof@burghardt.pl>");
    rLog(Info, "http://clamfs.sourceforge.net/");

    /*
     * Check if we have one argument (other arguments are assumed rLog related)
     */
    if (argc < 2) {
	rLog(Warn, "ClamFS need to be invoked with one parameter - location of configuration file");
	rLog(Warn, "Example: %s /etc/clamfs/home.xml", argv[0]);
	return EXIT_FAILURE;
    }

    /*
     * Load XML configuration file, parse it and fill in map<...> config
     */
    ConfigParserXML cp(argv[1]);
    if (config.size() == 0) {
	rLog(Warn, "No configuration has been loaded");
	return EXIT_FAILURE;
    }

#ifndef NDEBUG
    /*
     * Dump configuration form map <...>
     */
    cout << "--- begin of config dump ---" << endl;
    map <const char *, char *, ltstr>::iterator m_begin = config.begin();
    map <const char *, char *, ltstr>::iterator m_end   = config.end();
    while ( m_begin != m_end ) {
	cout << (*m_begin).first << ": " << (*m_begin).second << endl;
	++m_begin;
    }
    cout << "--- end of config dump ---" << endl;
#endif

    /*
     * Build argv for libFUSE
     */
    fuse_argv = new char *[FUSE_MAX_ARGS];
    memset(fuse_argv, 0, 32 * sizeof(char *)); /* set pointers to NULL */
    fuse_argc = 0;
    fuse_argv[fuse_argc++] = argv[0]; /* copy program name */
    fuse_argv[fuse_argc++] = config["mountpoint"]; /* set mountpoint */

    if (strncmp(config["public"], "yes", 3) == 0) {
	fuse_argv[fuse_argc++] = "-o";
	fuse_argv[fuse_argc++] = "allow_other,default_permissions";
    }
    
    if ((config["threads"] != NULL) &&
        (strncmp(config["threads"], "no", 2) == 0))
	fuse_argv[fuse_argc++] = "-s";

    if ((config["fork"] != NULL) &&
        (strncmp(config["fork"], "no", 2) == 0))
	fuse_argv[fuse_argc++] = "-f";

    /*
     * Change our current directory to "root" of our filesystem
     */
    rLog(Info,"chdir to our 'root' (%s)",config["root"]);
    if (chdir(config["root"]) < 0) {
	int err = errno; /* copy errno, rLog can overwrite */
	rLog(Warn, "chdir failed: %s", strerror(err));
	return err;
    }
    savefd = open(".", 0);

    /*
     * Check if clamd is available for clamfs
     */
    if ((ret = OpenClamav(config["socket"])) != 0) {
	rLog(Warn, "cannot start without running clamd, make sure it works");
	return ret;
    }

    if ((ret = PingClamav()) != 0) {
	rLog(Warn, "cannot start without running clamd, make sure it works");
	return ret;
    }
    CloseClamav();

    /*
     * Initialize cache
     */
    if (atoi(config["entries"]) <= 0) {
	rLog(Warn, "maximal cache entries count cannot be =< 0");
	return EXIT_FAILURE;
    }
    if (atoi(config["expire"]) <= 0) {
	rLog(Warn, "maximal cache expire value cannot be =< 0");
	return EXIT_FAILURE;
    }
    cache = new ScanCache(atoi(config["entries"]), atoi(config["expire"]));

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
		rLog(Warn, "logging method 'file' choosen, but no log 'filename' given");
		return EXIT_FAILURE;
	    }		
	}
    }

    /*
     * Start FUSE
     */
    ret = fuse_main(fuse_argc, fuse_argv, &clamfs_oper);
    
    rLog(Info, "deleting cache");
    delete cache;
    cache = NULL;

    rLog(Info, "closing logging targets");
    RLogCloseLogFile();

    rLog(Warn,"exiting");
#ifdef DMALLOC
    dmalloc_verify(0L);
#endif
    return ret;
}

/* EoF */
