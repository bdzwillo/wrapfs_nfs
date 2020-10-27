/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"

#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
int wrapfs_check_write(struct dentry *dentry, struct super_block *sb, const char *op)
{
	if (!WRAPFS_SB(sb)->rdonly) {
		return 0;
	}
	if (WRAPFS_SB(sb)->single_uid && (WRAPFS_SB(sb)->single_uid != current_uid().val)) {
		return 0;
	}
	pr_debug("wrapfs: deny(%s) %pd4\n", op, dentry);
	return -EACCES;
}
#endif

static int wrapfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	/* S_ modes are defined in include/fcntl.h
	 */
	pr_debug("wrapfs: create(%pd4, 0%o)\n", dentry, mode);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(dentry, dir->i_sb, "create"))) {
		return err;
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_parent_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
out:
	unlock_dir(lower_parent_dentry);
	return err;
}

static int wrapfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;

	pr_debug("wrapfs: link(%pd4, %pd4)\n", old_dentry, new_dentry);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(new_dentry, dir->i_sb, "link"))) {
		return err;
	}
#endif
	file_size_save = i_size_read(old_dentry->d_inode);
	lower_old_dentry = wrapfs_get_lower_dentry(old_dentry);
	lower_new_dentry = wrapfs_get_lower_dentry(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		       lower_new_dentry, NULL);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = wrapfs_interpose(new_dentry, dir->i_sb, lower_new_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		  wrapfs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return err;
}

static int wrapfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = wrapfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;

	pr_debug("wrapfs: unlink(%pd4)\n", dentry);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(dentry, dir->i_sb, "unlink"))) {
		return err;
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS below.  
	 * Silly-renamed files will get deleted by NFS later on.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED) {
		pr_debug("wrapfs: unlink %pd4 -> NFS SILLY RENAMED\n", dentry);
	}
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode,
		  wrapfs_lower_inode(dentry->d_inode)->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	return err;
}

static int wrapfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	pr_debug("wrapfs: symlink(\"%s\", %pd4)\n", symname, dentry);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(dentry, dir->i_sb, "symlink"))) {
		return err;
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	dget(lower_dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (err)
		goto out;
	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_parent_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
out:
	unlock_dir(lower_parent_dentry);
	dput(lower_dentry);
 	if (!dentry->d_inode)
		d_drop(dentry);
	return err;
}

static int wrapfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	pr_debug("wrapfs: mkdir(%pd4, 0%o)\n", dentry, mode);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(dentry, dir->i_sb, "mkdir"))) {
		return err;
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/* update number of links on parent directory */
	set_nlink(dir, wrapfs_lower_inode(dir)->i_nlink);
out:
	unlock_dir(lower_parent_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return err;
}

static int wrapfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct inode *lower_dir_inode;
	int err;

	pr_debug("wrapfs: rmdir(%pd4)\n", dentry);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(dentry, dir->i_sb, "rmdir"))) {
		return err;
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	dget(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	lower_dir_inode = lower_dir_dentry->d_inode;

	dget(lower_dentry);
	err = vfs_rmdir(lower_dir_inode, lower_dentry);
	dput(lower_dentry);
	if (err)
		goto out;

	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dir, lower_dir_inode->i_nlink);
out:
	unlock_dir(lower_dir_dentry);
	if (!err)
		d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	dput(dentry);
	return err;
}

static int wrapfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	pr_debug("wrapfs: mknod(%pd4, 0%o, 0%o)\n", dentry, mode, dev);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(dentry, dir->i_sb, "mknod"))) {
		return err;
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_parent_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
out:
	unlock_dir(lower_parent_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return err;
}

/*
 * The locking rules in wrapfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int wrapfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;

	pr_debug("wrapfs: rename(%pd4, %pd4)\n", old_dentry, new_dentry);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if ((err = wrapfs_check_write(old_dentry, old_dir->i_sb, "rename-from"))) {
		return err;
	}
	if ((err = wrapfs_check_write(new_dentry, new_dir->i_sb, "rename-to"))) {
		return err;
	}
#endif
	lower_old_dentry = wrapfs_get_lower_dentry(old_dentry);
	lower_new_dentry = wrapfs_get_lower_dentry(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
					lower_old_dir_dentry->d_inode);
	}
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return err;
}

static int wrapfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: readlink(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!lower_dentry->d_inode->i_op ||
	    !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);
out:
	return err;
}

static void *wrapfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = wrapfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);
	return NULL;
}

static int wrapfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	/* MAY_ flags are defined in include/linux/fs.h:
	 * MAY_EXEC                0x00000001
	 * MAY_WRITE               0x00000002
	 * MAY_READ                0x00000004
	 * MAY_APPEND              0x00000008
	 * MAY_ACCESS              0x00000010
	 * MAY_OPEN                0x00000020
	 * MAY_CHDIR               0x00000040
	 */
	if ((mask & MAY_OPEN) && (mask & MAY_WRITE)) {
		/* no path info available here -> have to wrap file open()
		 */
		pr_debug("wrapfs: permission_open_write(%s:%lu, 0x%x)\n", inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0, mask);
	}
	lower_inode = wrapfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int wrapfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct iattr lower_ia;

	/* ATTR_ flags are defined in include/linux/fs.h
	 */
	pr_debug("wrapfs: setattr(%pd4, 0x%x)\n", dentry, ia->ia_valid);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if (WRAPFS_SB(dentry->d_sb)) {
		if ((err = wrapfs_check_write(dentry, dentry->d_sb, "setattr"))) {
			return err;
		}
	}
#endif
	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out;

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_inode = wrapfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));

	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = wrapfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */
out:
	return err;
}

static int wrapfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err = 0;
	struct kstat lower_stat;
	struct dentry *lower_dentry;
	struct vfsmount *lower_mnt;

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_mnt    = wrapfs_get_lower_path(dentry)->mnt;

	if (!lower_dentry->d_inode->i_op->getattr)
		goto out;
	err = lower_dentry->d_inode->i_op->getattr(lower_mnt, lower_dentry, &lower_stat);

	pr_debug("wrapfs: getattr(%pd4) = %d\n", dentry, err);

	if (err)
		goto out;
	fsstack_copy_attr_all(dentry->d_inode, wrapfs_lower_inode(dentry->d_inode));
	if (lower_dentry->d_flags & DCACHE_OP_REVALIDATE) {
		/* on top of nfs or other remote filesystem i_size/i_blocks
		 * might have changed after the last revalidate.
		 */
		fsstack_copy_inode_size(dentry->d_inode, wrapfs_lower_inode(dentry->d_inode));
	} else {
		stat->blocks = wrapfs_lower_inode(dentry->d_inode)->i_blocks;
	}
	generic_fillattr(dentry->d_inode, stat);
out:
	return err;
}

static int
wrapfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;

	pr_debug("setxattr(%pd4, \"%s\", \"%*pE\", %zu, 0x%x)\n", dentry, name, min((int)size, 48), value, size, flags);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if (WRAPFS_SB(dentry->d_sb)) {
		if ((err = wrapfs_check_write(dentry, dentry->d_sb, "setxattr"))) {
			return err;
		}
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!lower_dentry->d_inode->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(dentry->d_inode, lower_dentry->d_inode);
out:
	return err;
}

static ssize_t
wrapfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: getxattr(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!lower_dentry->d_inode->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = lower_dentry->d_inode->i_op->getxattr(lower_dentry, name, buffer, size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);
out:
	return err;
}

static ssize_t
wrapfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: listxattr(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!lower_dentry->d_inode->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = lower_dentry->d_inode->i_op->listxattr(lower_dentry, buffer, buffer_size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);
out:
	return err;
}

static int
wrapfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: removexattr(%pd4, \"%s\")\n", dentry, name);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
	if (WRAPFS_SB(dentry->d_sb)) {
		if ((err = wrapfs_check_write(dentry, dentry->d_sb, "removexattr"))) {
			return err;
		}
	}
#endif
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!lower_dentry->d_inode->i_op->removexattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;
	fsstack_copy_attr_all(dentry->d_inode, lower_dentry->d_inode);
out:
	return err;
}

const struct inode_operations wrapfs_symlink_iops = {
	.readlink	= wrapfs_readlink,
	.permission	= wrapfs_permission,
	.follow_link	= wrapfs_follow_link,
	.setattr	= wrapfs_setattr,
	.getattr	= wrapfs_getattr,
	.put_link	= kfree_put_link,
	.setxattr	= wrapfs_setxattr,
	.getxattr	= wrapfs_getxattr,
	.listxattr	= wrapfs_listxattr,
	.removexattr	= wrapfs_removexattr,
};

const struct inode_operations wrapfs_dir_iops = {
	.create		= wrapfs_create,
	.lookup		= wrapfs_lookup,
	.link		= wrapfs_link,
	.unlink		= wrapfs_unlink,
	.symlink	= wrapfs_symlink,
	.mkdir		= wrapfs_mkdir,
	.rmdir		= wrapfs_rmdir,
	.mknod		= wrapfs_mknod,
	.rename		= wrapfs_rename,
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,
	.getattr	= wrapfs_getattr,
	.setxattr	= wrapfs_setxattr,
	.getxattr	= wrapfs_getxattr,
	.listxattr	= wrapfs_listxattr,
	.removexattr	= wrapfs_removexattr,
};

const struct inode_operations wrapfs_main_iops = {
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,
	.getattr	= wrapfs_getattr,
	.setxattr	= wrapfs_setxattr,
	.getxattr	= wrapfs_getxattr,
	.listxattr	= wrapfs_listxattr,
	.removexattr	= wrapfs_removexattr,
};
