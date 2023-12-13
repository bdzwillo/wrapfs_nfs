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

static ssize_t wrapfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = wrapfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = wrapfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

/* For ->iterate() the caller holds the file->f_inode lock.
 * (see: Documentation/filesystems/locking)
 */
static int wrapfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	pr_debug("wrapfs: readdir(%pD4)\n", file);

	lower_file = wrapfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	struct file *lower_file;

	pr_debug("wrapfs: mmap(%pD4, 0x%lx)\n", file, vma->vm_flags);

	lower_file = wrapfs_lower_file(file);

	if (!lower_file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
 		return -EIO;

	vma->vm_file = get_file(lower_file);

	err = lower_file->f_op->mmap(lower_file, vma);
	if (err) {
		/* Drop reference count from new vm_file value */
		fput(lower_file);
	} else {
		/* Drop reference count from previous vm_file value */
		fput(file);
	}
	file_accessed(file);

	return err;
}

/* The caller of ->open() holds no inode lock. 
 * The caller also holds a reference on f->f_path.dentry & f->f_path.mnt
 * (see: Documentation/filesystems/Locking)
 */
static int wrapfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	pr_debug("wrapfs: open(%pD4, %s:%lu, 0%o)\n", file, inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0, file->f_flags);

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
	if (!WRAPFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link wrapfs's file struct to lower's
	 * (dentry_open()->do_dentry_open() will hold a reference on lower_path)
	 */
	pathcpy(&lower_path, &WRAPFS_D(file->f_path.dentry)->lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = wrapfs_lower_file(file);
		if (lower_file) {
			wrapfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
		file->f_mode |= FMODE_KABI_ITERATE;
	}

	if (err)
		kfree(WRAPFS_F(file));
	else
		fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
out_err:
	return err;
}

static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	pr_debug("wrapfs: file_release(%pD4, %s:%lu)\n", file, inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0);

	lower_file = wrapfs_lower_file(file);
	if (lower_file) {
#if defined(WRAP_REMOTE_FILE_LOCKS)
		struct inode *inode_lower = locks_inode(lower_file);

		/* Avoid 'leftover lock' warnings from locks_remove_file() when
		 * a process does not unlock a posix lock.
		 *
		 * The file_lock list is located at the lower inode and fl_file
		 * points to lower_file (the lock request is copied in 
		 * posix_lock_file() when it is inserted to the i_flock list).
		 *
		 * Unlock of posix locks is not triggered when an overlayfs is
		 * mounted on top, because filp_close() does not see the i_flock
		 * of the lower_file. 
		 *
		 * So the unlock the lower posix locks is triggerd here with
		 * the matching owner, when the last reference to the file is
		 * removed.
		 */
		if (inode_lower->i_flock) {
			int n = 0;
			int o = 0;
			struct file_lock *fl;
			fl_owner_t owner = current->files; // default owner of non-OFD posix locks

			spin_lock(&inode_lower->i_lock);
			for (fl = inode_lower->i_flock; fl != NULL; fl = fl->fl_next) {
				if (fl->fl_flags & FL_POSIX) {
					if (fl->fl_file == lower_file) {
						owner = fl->fl_owner;
						o++;
					}
				}
				n++;
			}
			spin_unlock(&inode_lower->i_lock);
			if (o) {
				locks_remove_posix(lower_file, owner);
				pr_debug("wrapfs: file_release(%pD4) remove posix lock (%s:%lu) nlocks %d owned %d\n", file, inode_lower->i_sb->s_id, inode_lower->i_ino, n, o);
			}
		}
#endif
		wrapfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(WRAPFS_F(file));
	return 0;
}

static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = wrapfs_lower_file(file);
	err = vfs_fsync_range(lower_file, start, end, datasync);
out:
	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t wrapfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = wrapfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

static ssize_t wrapfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = wrapfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

#if defined(WRAP_REMOTE_FILE_LOCKS)
static inline bool is_remote_lock(struct file *filp)
{
        return likely(!(filp->f_path.dentry->d_sb->s_flags & MS_NOREMOTELOCK));
}

static int wrapfs_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	int err;
	struct file *lower_file;

	/* F_*LK cmds are defined in fcntl.h (F_GETLK=5, F_SETLK=6, F_SETLKW=7)
 	 * F_*LCK types are defined in fcntl.h (F_RDLCK=0, F_WRLCK=1, F_UNLCK=2)
	 * FL_* flags are defined in linux/fs.h (FL_POSIX=1, FL_FLOCK=2, FL_SLEEP=128, ..)
	 *
	 * posix locks use 'fl->fl_owner == current->files' here.
	 */
	pr_debug("wrapfs: lock(%pD4, %d, t=0x%x, fl=0x%x, r=%lld:%lld)\n", filp, cmd, fl->fl_type, fl->fl_flags, (long long)fl->fl_start, (long long)fl->fl_end);

	lower_file = wrapfs_lower_file(filp);
	get_file(lower_file); /* prevent lower_file from being released */
	fl->fl_file = lower_file;
	if (lower_file->f_op && lower_file->f_op->lock && is_remote_lock(lower_file)) {
		err = lower_file->f_op->lock(lower_file, cmd, fl);
	} else {
		err = posix_lock_file(lower_file, fl, NULL);
	}
	fl->fl_file = filp;
	fput(lower_file);
	return err;
}

static int wrapfs_flock(struct file *filp, int cmd, struct file_lock *fl)
{
	int err;
	struct file *lower_file;

	/* F_*LK cmds are defined in fctnl.h ((flock_cmd & LOCK_NB) ? F_SETLK=6 : F_SETLKW=7)
 	 * F_*LCK types are defined in fcntl.h (F_RDLCK=0 (flock_cmd:LOCK_SH), F_WRLCK=1 (flock_cmd:LOCK_EX), F_UNLCK=2 (flock_cmd:LOCK_UN))
	 * FL_* flags are defined in linux/fs.h (FL_POSIX=1, FL_FLOCK=2, FL_SLEEP=128, ..)
	 *
	 * flocks use 'fl->fl_owner == filp' here.
	 */
	pr_debug("wrapfs: flock(%pD4, %d, t=0x%x, fl=0x%x)\n", filp, cmd, fl->fl_type, fl->fl_flags);

	lower_file = wrapfs_lower_file(filp);
	get_file(lower_file); /* prevent lower_file from being released */
	fl->fl_file = lower_file;
	if (lower_file->f_op && lower_file->f_op->flock && is_remote_lock(lower_file)) {
		err = lower_file->f_op->flock(lower_file, cmd, fl);
	} else {
		err = locks_lock_file_wait(lower_file, fl);
	}
	fl->fl_file = filp;
	fput(lower_file);
	return err;
}
#endif

/*
 * For directories wrapfs cannot use generic_file_llseek as ->llseek,
 * because it would only set the offset of the upper file. It is also
 * necessary to call the llseek operation of the lower filesystem,
 * because filesystems like nfs implement a differing logic from
 * generic_file_llseek.
 *
 * For regular files generic_file_llseek is sufficient, because all
 * the read()/write() calls are called with a file->f_pos parameter
 * from the vfs-layer.
 *
 * note: It should be safe to acquire the inode mutex or just to use
 *       i_size_read() here. This does not protect the file->f_pos
 *       against concurrent modifications since this is something the
 *       userspace has to take care about.
 *       (see: Documentation/filesystems/Locking) 
 */
static loff_t wrapfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	mutex_lock(&file->f_path.dentry->d_inode->i_mutex);
	err = vfs_llseek(lower_file, offset, whence);
	file->f_pos = lower_file->f_pos;
	mutex_unlock(&file->f_path.dentry->d_inode->i_mutex);

	return err;
}

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
	.aio_read	= wrapfs_aio_read,
	.aio_write	= wrapfs_aio_write,
#if defined(WRAP_REMOTE_FILE_LOCKS)
	.lock		= wrapfs_lock,
	.flock		= wrapfs_flock,
#endif
};

/* trimmed directory options 
 *
 * note: for an underlying nfs it is required to map the directory file ops,
 *       because nfs_opendir(inode, file) uses the inode spinlock to protect
 *       a list_add() operation, and nfs_closedir(inode, file) uses the
 *       d_inode(file->f_path.dentry) spinlock to protect the list_del().
 *       (when the directory ops are not mapped, these are not the same objects)
 */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= wrapfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};
