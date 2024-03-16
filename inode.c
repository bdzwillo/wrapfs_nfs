/*
 * Copyright (c) 1998-2020 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2020 Stony Brook University
 * Copyright (c) 2003-2020 The Research Foundation of SUNY
 * Copyright (c) 2020-2021 Barnim Dzwillo @ Strato AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"

/* For ->create() the caller holds the inode lock on dir.
 * The caller also holds a reference on dentry.
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	/* S_ modes are defined in include/fcntl.h
	 */
	pr_debug("wrapfs: create(%pd4, 0%o)\n", dentry, mode);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_parent_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
out:
	unlock_dir(lower_parent_dentry);
	return err;
}

/* For ->link() the caller holds the inode locks on dir and on the
 * victim d_inode(old_dentry). The caller also holds a reference
 * on old_dentry & new_dentry;
 * (see: Documentation/filesystems/directory-locking)
 */
static int wrapfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;

	pr_debug("wrapfs: link(%pd4, %pd4)\n", old_dentry, new_dentry);

	file_size_save = i_size_read(d_inode(old_dentry));
	lower_old_dentry = wrapfs_get_lower_dentry(old_dentry);
	lower_new_dentry = wrapfs_get_lower_dentry(new_dentry);
	lower_dir_dentry = lock_parent(lower_new_dentry);

	/* todo: might handle &delegated_inode to avoid nfs long delegation break */
	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = wrapfs_interpose(new_dentry, dir->i_sb, lower_new_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(d_inode(old_dentry),
		  wrapfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	return err;
}

/* For ->unlink() the caller holds the inode locks on dir and on the
 * victim d_inode(dentry). The caller also holds a reference on dentry.
 * (see: Documentation/filesystems/directory-locking)
 */
static int wrapfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = wrapfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;

	pr_debug("wrapfs: unlink(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	/* check that underlying dentry of victim is still hashed and
	 * has the right parent - it can be moved, but it can't be moved to/from
	 * the directory we are holding exclusive.  So while ->d_parent itself
	 * might not be stable, the result of comparison is
	 */
	if (lower_dentry->d_parent != lower_dir_dentry) {
		pr_debug("wrapfs: unlink(%pd4) warn: lower parent mismatch", dentry);
		err = -EINVAL;
	} else if (d_unhashed(lower_dentry)) {
		pr_debug("wrapfs: unlink(%pd4) warn: lower unhashed", dentry);
		err = -EINVAL;
	} else {
		/* todo: might handle &delegated_inode to avoid nfs long delegation break */
		err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	}

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
	set_nlink(d_inode(dentry),
		  wrapfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	return err;
}

/* For ->symlink() the caller holds the inode lock on dir.
 * The caller also holds a reference on dentry.
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	pr_debug("wrapfs: symlink(\"%s\", %pd4)\n", symname, dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	if (!d_inode(lower_dentry)) {
		pr_debug("wrapfs: symlink(%pd4) warn: lower dentry negative", dentry);
		goto out;
	}
	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_parent_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
out:
	unlock_dir(lower_parent_dentry);
 	if (!d_inode(dentry))
		d_drop(dentry);
	return err;
}

/* For ->mkdir() the caller holds the inode lock on dir.
 * The caller also holds a reference on dentry.
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	pr_debug("wrapfs: mkdir(%pd4, 0%o)\n", dentry, mode);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;
	if (!d_inode(lower_dentry)) {
		pr_debug("wrapfs: mkdir(%pd4) warn: lower dentry negative", dentry);
		goto out;
	}
	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, d_inode(lower_parent_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, d_inode(lower_parent_dentry)->i_nlink);
out:
	unlock_dir(lower_parent_dentry);
	if (!d_inode(dentry))
		d_drop(dentry);
	return err;
}

/* For ->rmdir() the caller holds the inode locks on dir and on the
 * victim d_inode(dentry). The caller also holds a reference on dentry.
 * (see: Documentation/filesystems/directory-locking)
 */
static int wrapfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct inode *lower_dir_inode;
	int err;

	pr_debug("wrapfs: rmdir(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	dget(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	lower_dir_inode = d_inode(lower_dir_dentry);

	/* check that underlying dentry of victim is still hashed and
	 * has the right parent - it can be moved, but it can't be moved to/from
	 * the directory we are holding exclusive.  So while ->d_parent itself
	 * might not be stable, the result of comparison is
	 */
	dget(lower_dentry);
	if (lower_dentry->d_parent != lower_dir_dentry) {
		pr_debug("wrapfs: rmdir(%pd4) warn: lower parent mismatch", dentry);
		err = -EINVAL;
	} else if (d_unhashed(lower_dentry)) {
		pr_debug("wrapfs: rmdir(%pd4) warn: lower unhashed", dentry);
		err = -EINVAL;
	} else {
		err = vfs_rmdir(lower_dir_inode, lower_dentry);
	}
	dput(lower_dentry);
	if (err)
		goto out;

	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
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

/* For ->mknod() the caller holds the inode lock on dir.
 * The caller also holds a reference on dentry.
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;

	pr_debug("wrapfs: mknod(%pd4, 0%o, 0%o)\n", dentry, mode, dev);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;
	if (!d_inode(lower_dentry)) {
		pr_debug("wrapfs: mknod(%pd4) warn: lower dentry negative", dentry);
		goto out;
	}
	err = wrapfs_interpose(dentry, dir->i_sb, lower_dentry);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_parent_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
out:
	unlock_dir(lower_parent_dentry);
	if (!d_inode(dentry))
		d_drop(dentry);
	return err;
}

/*
 * For ->rename() between different directorys, the caller holds the superblock
 * lock i_sb->s_vfs_rename_mutex and the inode locks on old_dir and new_dir.
 * For ->rename() in the same directory just the old_dir inode lock is held.
 * The caller also holds the inode locks on the victims d_inode(new_dentry)
 * and d_inode(old_dentry) (if old_entry is not a directory).
 * The caller also holds references on old_dentry and new_dentry.
 * (see: Documentation/filesystems/directory-locking)
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

	lower_old_dentry = wrapfs_get_lower_dentry(old_dentry);
	lower_new_dentry = wrapfs_get_lower_dentry(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);

	/* check that dentries still have the same parents and are not unlinked */
	err = -EINVAL;
	if (lower_old_dentry->d_parent != lower_old_dir_dentry) {
		pr_debug("wrapfs: rename(%pd4) warn: lower old parent mismatch", old_dentry);
		goto out;
	}
	if (lower_new_dentry->d_parent != lower_new_dir_dentry) {
		pr_debug("wrapfs: rename(%pd4) warn: lower new parent mismatch", old_dentry);
		goto out;
	}
	if (d_unhashed(lower_old_dentry) || d_unhashed(lower_new_dentry)) {
		pr_debug("wrapfs: rename(%pd4) warn: lower unhashed", old_dentry);
		goto out;
	}
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

	/* todo: might handle &delegated_inode to avoid nfs long delegation break */
	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return err;
}

/* For ->readlink() the caller holds *no* inode lock on d_inode(dentry)
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: readlink(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));
out:
	return err;
}

/* For ->follow_link() the caller holds *no* inode lock on d_inode(dentry)
 * (see: Documentation/filesystems/Locking)
 */
static void *wrapfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	//pr_debug("wrapfs: follow_link(%pd4)\n", dentry);

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

/* For ->permission() the caller holds *no* inode lock on d_inode(dentry)
 * Also ->permission() may not block if called in rcu-walk mode (mask & MAY_NOT_BLOCK).
 * (see: Documentation/filesystems/Locking)
 */
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
	 * MAY_NOT_BLOCK           0x00000080
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

/* For ->setattr() the caller holds the inode lock on d_inode(dentry).
 * (see: Documentation/filesystems/Locking)
 */
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

	inode = d_inode(dentry);

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
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
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

/* For ->getattr() the caller holds *no* inode lock on d_inode(dentry)
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err = 0;
	struct kstat lower_stat;
	struct dentry *lower_dentry;
	struct vfsmount *lower_mnt;

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	lower_mnt    = wrapfs_get_lower_path(dentry)->mnt;

	if (d_inode(lower_dentry)->i_op->getattr)
		err = d_inode(lower_dentry)->i_op->getattr(lower_mnt, lower_dentry, &lower_stat);

	pr_debug("wrapfs: getattr(%pd4) = %d\n", dentry, err);

	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry), wrapfs_lower_inode(d_inode(dentry)));
	if (lower_dentry->d_flags & DCACHE_OP_REVALIDATE) {
		/* on top of nfs or other remote filesystem i_size/i_blocks
		 * might have changed after the last revalidate.
		 */
		fsstack_copy_inode_size(d_inode(dentry), wrapfs_lower_inode(d_inode(dentry)));
	} else {
		stat->blocks = wrapfs_lower_inode(d_inode(dentry))->i_blocks;
	}
	generic_fillattr(d_inode(dentry), stat);
out:
	return err;
}

/* For ->setxattr() the caller holds the inode lock on d_inode(dentry).
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;

	pr_debug("wrapfs: setxattr(%pd4, \"%s\", \"%*pE\", %zu, 0x%x)\n", dentry, name, min((int)size, 48), value, size, flags);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	if (!d_inode(lower_dentry)) {
		pr_debug("wrapfs: setxattr(%pd4) warn: lower_dentry negative", dentry);
		goto out;
	}
	fsstack_copy_attr_all(d_inode(dentry), d_inode(lower_dentry));
out:
	return err;
}

/* For ->getxattr() the caller holds *no* inode lock on d_inode(dentry)
 * (see: Documentation/filesystems/Locking)
 */
static ssize_t wrapfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: getxattr(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	inode_lock(d_inode(lower_dentry));
	err = d_inode(lower_dentry)->i_op->getxattr(lower_dentry, name, buffer, size);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));
out:
	return err;
}

/* For ->listxattr() the caller holds *no* inode lock on d_inode(dentry)
 * (see: Documentation/filesystems/Locking)
 */
static ssize_t wrapfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: listxattr(%pd4)\n", dentry);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	inode_lock(d_inode(lower_dentry));
	err = d_inode(lower_dentry)->i_op->listxattr(lower_dentry, buffer, buffer_size);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));
out:
	return err;
}

/* For ->removexattr() the caller holds the inode lock on d_inode(dentry).
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;

	pr_debug("wrapfs: removexattr(%pd4, \"%s\")\n", dentry, name);

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!d_inode(lower_dentry)->i_op->removexattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	inode_lock(d_inode(lower_dentry));
	err = d_inode(lower_dentry)->i_op->removexattr(lower_dentry, name);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry), d_inode(lower_dentry));
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

#ifdef USE_RH7_IOPS_WRAPPER
const struct inode_operations_wrapper wrapfs_dir_iops = {
	.ops = {
#else
const struct inode_operations wrapfs_dir_iops = {
#endif
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
#ifdef USE_RH7_IOPS_WRAPPER
	},
#endif
};

#ifdef USE_RH7_IOPS_WRAPPER
const struct inode_operations_wrapper wrapfs_main_iops = {
	.ops = {
#else
const struct inode_operations wrapfs_main_iops = {
#endif
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,
	.getattr	= wrapfs_getattr,
	.setxattr	= wrapfs_setxattr,
	.getxattr	= wrapfs_getxattr,
	.listxattr	= wrapfs_listxattr,
	.removexattr	= wrapfs_removexattr,
#ifdef USE_RH7_IOPS_WRAPPER
	},
#endif
};
