/*!\file clamfs.cxx

   \brief ClamFS main file

   $Id: clamfs.cxx,v 1.7 2007-02-12 00:42:40 burghardt Exp $

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

*//*

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

/*!\namespace clamfs
   \brief ClamFS own namespace
*/
namespace clamfs {

/*!\brief Saved file descriptor of our base directory */
static int savefd;
/*!\brief Stores all configuration options names and values */
map <const char *, char *, ltstr> config;
/*!\brief ScanCache instance (need by all threads thus global) */
ScanCache *cache = NULL;
/*!\brief Mutex need to serialize access to clamd (need by all threads thus global) */
FastMutex scanMutex;

extern "C" {

/*!\brief Fixes file path by prefixing it with "." (dot)
   \param path path need to be fixed
   \returns fixed path
*/
static inline char* fixpath(const char* path)
{
    char* fixed=new char[strlen(path)+2];
    
    fchdir(savefd);
    strcpy(fixed,".");
    strcat(fixed,path);
    
    return fixed;
}

/*!\brief FUSE getattr() callback
   \param path file path
   \param stbuf buffer to pass to lstat()
   \returns 0 if lstat() returns without error on -errno otherwise
*/
static int clamfs_getattr(const char *path, struct stat *stbuf)
{
    int res;

    path = fixpath(path);
    res = lstat(path, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE fgetattr() callback
   \param path file path
   \param stbuf buffer to pass to lstat()
   \param fi information about open files
   \returns 0 if lstat() returns without error on -errno otherwise
*/
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

/*!\brief FUSE access() callback
   \param path file path
   \param mask bit pattern
   \returns 0 if access() returns without error on -errno otherwise
*/
static int clamfs_access(const char *path, int mask)
{
    int res;

    path = fixpath(path);
    res = access(path, mask);
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
    int res;

    path = fixpath(path);
    res = readlink(path, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

/*!\brief FUSE opendir() callback
   \param path directory path
   \param fi information about open files
   \returns 0 if opendir() returns without error on -errno otherwise
*/
static int clamfs_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;

    path = fixpath(path);
    dp = opendir(path);
    if (dp == NULL)
        return -errno;

    fi->fh = (unsigned long) dp;
    return 0;
}

/*!\brief Returns directory pointer from fuse_file_info
   \param fi information about open files
   \returns pointer to file handle
*/
static inline DIR *get_dirp(struct fuse_file_info *fi)
{
    return (DIR *) (uintptr_t) fi->fh;
}

/*!\brief FUSE readdir() callback
   \param path directory path
   \param buf data buffer
   \param filler directory content filter
   \param offset directory poninter offset
   \param fi information about open files
   \returns always 0
*/
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

/*!\brief FUSE releasedir() callback
   \param path directory path
   \param fi information about open files
   \returns always 0
*/
static int clamfs_releasedir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp = get_dirp(fi);
    (void) path;
    closedir(dp);
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

    path = fixpath(path);
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

/*!\brief FUSE mkdir() callback
   \param path file path
   \param mode file permissions
   \returns 0 if mkdir() returns without error on -errno otherwise
*/
static int clamfs_mkdir(const char *path, mode_t mode)
{
    int res;

    path = fixpath(path);
    res = mkdir(path, mode);
    if (res == -1)
        return -errno;
    else
	res = lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

/*!\brief FUSE unlink() callback
   \param path file path
   \returns 0 if unlink() returns without error on -errno otherwise
*/
static int clamfs_unlink(const char *path)
{
    int res;

    path = fixpath(path);
    res = unlink(path);
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

    path = fixpath(path);
    res = rmdir(path);
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

    from = fixpath(from);
    to = fixpath(to);
    res = symlink(from, to);
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
static int clamfs_rename(const char *from, const char *to)
{
    int res;

    from = fixpath(from);
    to = fixpath(to);
    res = rename(from, to);
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

    from = fixpath(from);
    to = fixpath(to);
    res = link(from, to);
    if (res == -1)
        return -errno;
    else
	res = lchown(from, fuse_get_context()->uid, fuse_get_context()->gid);

    return 0;
}

/*!\brief FUSE chmod() callback
   \param path file path
   \param mode file permissions
   \returns 0 if chmod() returns without error on -errno otherwise
*/
static int clamfs_chmod(const char *path, mode_t mode)
{
    int res;

    path = fixpath(path);
    res = chmod(path, mode);
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
static int clamfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    path = fixpath(path);
    res = lchown(path, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE truncate() callback
   \param path file path
   \param size requested size
   \returns 0 if truncate() returns without error on -errno otherwise
*/
static int clamfs_truncate(const char *path, off_t size)
{
    int res;

    path = fixpath(path);
    res = truncate(path, size);
    if (res == -1)
        return -errno;

    return 0;
}

/*!\brief FUSE ftruncate() callback
   \param path file path
   \param size requested size
   \param fi information about open files
   \returns 0 if ftruncate() returns without error on -errno otherwise
*/
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

/*!\brief FUSE utime() callback
   \param path file path
   \param buf data buffer
   \returns 0 if utime() returns without error on -errno otherwise
*/
static int clamfs_utime(const char *path, struct utimbuf *buf)
{
    int res;

    path = fixpath(path);
    res = utime(path, buf);
    if (res == -1)
        return -errno;

    return 0;
}

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

    path = fixpath(path);
    fd = open(path, fi->flags, mode);
    if (fd == -1)
        return -errno;
    else
	res = lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);

    fi->fh = fd;
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

    path = fixpath(path);
    fd = open(path, fi->flags);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

/*!\brief FUSE open() callback
   \param path file path
   \param fi information about open files
   \returns result of open_backend() call or -EPERM if virus is detected
*/
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
     * Check file size (if option defined)
     */
    if (config["maximal-size"] != NULL) {
	ret = lstat(real_path, &file_stat);
	if (!ret) { /* got file stat without error */
	    if (file_stat.st_size > atoi(config["maximal-size"])) { /* file too big */
		rLog(Warn, "file %s excluded from anti-virus scan because file is too big (file size: %ld bytes)",
		path, (long int)file_stat.st_size);
		return open_backend(path, fi);
	    }
	}
    }

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
		    return open_backend(path, fi);
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
		    return open_backend(path, fi);
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
		return open_backend(path, fi);
		
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
    int res;

    (void) path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
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
    int res;

    (void) path;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

/*!\brief FUSE statfs() callback
   \param path file path
   \param stbuf data buffer
   \returns 0 if statvfs() returns without error on -errno otherwise
*/
static int clamfs_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    path = fixpath(path);
    res = statvfs(path, stbuf);
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
    close(fi->fh);

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
        res = fdatasync(fi->fh);
    else
#endif
        res = fsync(fi->fh);
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
    path = fixpath(path);
    res = lsetxattr(path, name, value, size, flags);
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
    int res;
    path = fixpath(path);
    res = lgetxattr(path, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

/*!\brief FUSE listxattr() callback
   \param path file path
   \param list list of extended attribute names
   \param size size of list
   \returns 0 if llistxattr() returns without error on -errno otherwise
*/
static int clamfs_listxattr(const char *path, char *list, size_t size)
{
    int res;
    path = fixpath(path);
    res = llistxattr(path, list, size);
    if (res == -1)
        return -errno;
    return res;
}

/*!\brief FUSE removexattr() callback
   \param path file path
   \param name extended attribute name
   \returns 0 if lremovexattr() returns without error on -errno otherwise
*/
static int clamfs_removexattr(const char *path, const char *name)
{
    int res;
    path = fixpath(path);
    res = lremovexattr(path, name);
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
     * Open RLog
     */    
    RLogInit(argc, argv);
    RLogOpenStdio();

    rLog(Info, "ClamFS v"VERSION);
    rLog(Info, "Copyright (c) 2007 Krzysztof Burghardt <krzysztof@burghardt.pl>");
    rLog(Info, "http://clamfs.sourceforge.net/");

    /*
     * Check if we have one argument (other arguments are assumed RLog related)
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
    memset(fuse_argv, 0, 32 * sizeof(char *)); /* set pointers to NULL */
    fuse_argc = 0;
    fuse_argv[fuse_argc++] = argv[0]; /* copy program name */
    fuse_argv[fuse_argc++] = config["mountpoint"]; /* set mountpoint */

    if ((config["public"] != NULL) &&
        (strncmp(config["public"], "yes", 3) == 0)) {
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
	int err = errno; /* copy errno, RLog can overwrite */
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

} /* extern "C" */

} /* namespace clamfs */

/* EoF */
