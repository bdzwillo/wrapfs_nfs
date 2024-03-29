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

/* The dentry cache is just so we have properly sized dentries */
static struct kmem_cache *wrapfs_dentry_cachep;

int wrapfs_init_dentry_cache(void)
{
	wrapfs_dentry_cachep =
		kmem_cache_create("wrapfs_dentry",
				  sizeof(struct wrapfs_dentry_info),
				  0, SLAB_RECLAIM_ACCOUNT, NULL);

	return wrapfs_dentry_cachep ? 0 : -ENOMEM;
}

void wrapfs_destroy_dentry_cache(void)
{
	if (wrapfs_dentry_cachep)
		kmem_cache_destroy(wrapfs_dentry_cachep);
}

void wrapfs_free_dentry_private_data(struct dentry *dentry)
{
	if (!dentry || !dentry->d_fsdata)
		return;
	kmem_cache_free(wrapfs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

/* allocate new dentry private data */
int wrapfs_new_dentry_private_data(struct dentry *dentry)
{
	struct wrapfs_dentry_info *info = WRAPFS_D(dentry);

	/* use zalloc to init dentry_info.lower_path */
	info = kmem_cache_zalloc(wrapfs_dentry_cachep, GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	spin_lock_init(&info->lock);
	dentry->d_fsdata = info;

	return 0;
}

static int wrapfs_inode_test(struct inode *inode, void *candidate_lower_inode)
{
	struct inode *current_lower_inode = wrapfs_lower_inode(inode);
	if (current_lower_inode == (struct inode *)candidate_lower_inode)
		return 1; /* found a match */
	else
		return 0; /* no match */
}

static int wrapfs_inode_set(struct inode *inode, void *lower_inode)
{
	/* we do actual inode initialization in wrapfs_iget */
	return 0;
}

struct inode *_wrapfs_iget(struct super_block *sb, struct inode *lower_inode)
{
	struct inode *inode; /* the new inode to return */

	if (!igrab(lower_inode))
		return ERR_PTR(-ESTALE);
	inode = iget5_locked(sb, /* our superblock */
			     /*
			      * hashval: we use inode number, but we can
			      * also use "(unsigned long)lower_inode"
			      * instead.
			      */
			     lower_inode->i_ino, /* hashval */
			     wrapfs_inode_test,	/* inode comparison function */
			     wrapfs_inode_set, /* inode init function */
			     lower_inode); /* data passed to test+set fxns */
	if (!inode) {
		iput(lower_inode);
		return ERR_PTR(-ENOMEM);
	}
	/* if found a cached inode, then just return it (after iput) */
	if (!(inode->i_state & I_NEW)) {
		iput(lower_inode);
		return inode;
	}

	/* initialize new inode */
	inode->i_ino = lower_inode->i_ino;
	wrapfs_set_lower_inode(inode, lower_inode);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	atomic64_inc(&inode->i_version);
#else
	inode->i_version++;
#endif
	/* use different set of inode ops for symlinks & directories
	 *
	 * Note: redhat7 uses an inode_operations_wrapper struct to backport
	 *       some inode operations from newer kernels. The presence of this
	 *       extended struct is indicated by 'inode->i_flags & S_IOPS_WRAPPER'.
	 *
	 *       When the S_IOPS_WRAPPER flag is not aligned with the layout
	 *       of the iops struct, the vfs_rename-call will read an invalid
	 *       function pointer and crash the kernel.
	 */
	if (S_ISDIR(lower_inode->i_mode)) {
#ifdef USE_RH7_IOPS_WRAPPER
		inode->i_op = &wrapfs_dir_iops.ops;
#else
		inode->i_op = &wrapfs_dir_iops;
#endif
	} else if (S_ISLNK(lower_inode->i_mode)) {
		inode->i_op = &wrapfs_symlink_iops;
	} else {
#ifdef USE_RH7_IOPS_WRAPPER
		inode->i_op = &wrapfs_main_iops.ops;
#else
		inode->i_op = &wrapfs_main_iops;
#endif
	}
	/* use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode)) {
		inode->i_fop = &wrapfs_dir_fops;
	} else if (special_file(lower_inode->i_mode)) {
		init_special_inode(inode, lower_inode->i_mode, lower_inode->i_rdev);
	} else {
		inode->i_fop = &wrapfs_main_fops;
		inode->i_mapping->a_ops = &wrapfs_aops;
	}
	/* copy inode attributes (including i_atime, i_mtime, i_ctime) */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);

	return inode;
}

struct inode *wrapfs_iget(struct super_block *sb, struct inode *lower_inode)
{
	struct inode *inode = _wrapfs_iget(sb, lower_inode);

	if (!IS_ERR(inode) && (inode->i_state & I_NEW)) {
		unlock_new_inode(inode);
	}
	return inode;
}

/*
 * Helper interpose routine, called directly by ->lookup to handle
 * spliced dentries.
 */
static struct inode *wrapfs_get_inode(struct dentry *dentry,
					 struct super_block *sb,
					 struct inode *lower_inode)
{
	struct inode *inode;
	struct super_block *lower_sb;

	lower_sb = wrapfs_lower_super(sb);

	/* check that the lower file system didn't cross a mount point */
	if (lower_inode->i_sb != lower_sb) {
		return ERR_PTR(-EXDEV);
	}

	/*
	 * We allocate our new inode below by calling wrapfs_iget,
	 * which will initialize some of the new inode's fields
	 */

	/* inherit lower inode number for wrapfs's inode */
	inode = _wrapfs_iget(sb, lower_inode);
	return inode;
}

/*
 * Connect a wrapfs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: wrapfs's dentry which interposes on lower one
 * @sb: wrapfs's super_block
 * @lower_path: the lower path (caller does path_get/put)
 */
int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
		     struct dentry *lower_dentry)
{
	struct inode *inode;
	struct inode *lower_inode = d_inode(lower_dentry);

	inode = wrapfs_get_inode(dentry, sb, lower_inode);
	if (IS_ERR(inode)) {
		return PTR_ERR(inode);
	}
	/* d_instantiate_new() avoids inode locking races between
	 * unlock_new_inode() and d_instantiate().
	 */
	if (inode->i_state & I_NEW) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) || defined(USE_RH7_INSTANTIATE_NEW)
		d_instantiate_new(dentry, inode);
#else
		unlock_new_inode(inode);
		d_instantiate(dentry, inode);
#endif
	} else {
		d_instantiate(dentry, inode);
	}
	return 0;
}

/* For ->lookup() the caller holds the inode lock on dir.
 * The caller also holds a reference on dentry.
 * (see: Documentation/filesystems/Locking)
 *
 * Fills in positive/negative d_inode(dentry) on success.
 * - returns NULL if dentry passed as param is ok.
 * - returns a new dentry, if dentry was disconnected (the caller will call dput() on it)
 * - returns ERR_PTR if an error occurred.
 */
struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
			     unsigned int flags)
{
	int err;
	struct dentry *ret_dentry = NULL;
	struct dentry *lower_dir_dentry;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;

	lower_dir_dentry = wrapfs_get_lower_dentry(dentry->d_parent);
	lower_dir_mnt	 = wrapfs_get_lower_path(dentry->d_parent)->mnt;

 	lower_dentry = lookup_one_len_unlocked(dentry->d_name.name, lower_dir_dentry, dentry->d_name.len);
	if (IS_ERR(lower_dentry)) {
		pr_debug("wrapfs: lookup(%pd4, 0x%x) -> err %d\n", dentry, flags, (int)PTR_ERR(lower_dentry));
		ret_dentry = lower_dentry;
		goto out;
	}

	/* LOOKUP_ flags are defined in include/linux/namei_lookup.h
	 */
	pr_debug("wrapfs: lookup(%pd4, 0x%x) inode %s:%lu\n", dentry, flags, d_inode(lower_dentry) ? d_inode(lower_dentry)->i_sb->s_id : "NULL", d_inode(lower_dentry) ? d_inode(lower_dentry)->i_ino : 0);

	/* dentry->d_op ops are inherited from sb->s_d_op in d_alloc() */
	/* allocate dentry private data.  We free it in ->d_release */
	err = wrapfs_new_dentry_private_data(dentry);
	if (err) {
		ret_dentry = ERR_PTR(err);
		dput(lower_dentry);
		goto out;
	}
	lower_path.dentry = lower_dentry;
	lower_path.mnt = mntget(lower_dir_mnt);
	wrapfs_set_lower_path(dentry, &lower_path);

	/*
	 * negative dentry can go positive under us here - its parent is not
	 * locked.  That's OK and that could happen just as we return from
	 * lookup() anyway.  Just need to be careful and fetch
	 * ->d_inode only once - it's not stable here.
	 */
	lower_inode = READ_ONCE(lower_dentry->d_inode);
	if (!lower_inode) {
		ret_dentry = NULL;
		d_add(dentry, NULL); /* add negative dentry */
		goto out;
	}
	inode = wrapfs_get_inode(dentry, dentry->d_sb, lower_inode);
	if (IS_ERR(inode)) {
		ret_dentry = ERR_PTR(PTR_ERR(inode));
		/* path_put underlying path on error */
		wrapfs_put_reset_lower_path(dentry);
		goto out;
	}
	if (inode->i_state & I_NEW) {
		unlock_new_inode(inode);
	}
	/* update parent directory's atime
	 *
	 * note: there's nothing to prevent losing a timeslice to preemtion in
	 *       the middle of evaluation of d_inode(lower_dentry->d_parent),
	 *       having another process move lower_dentry around and have its
	 *       (ex)parent not pinned anymore and freed on memory pressure. 
	 *       Then we regain CPU and try to fetch ->d_inode from memory
	 *       that is freed by that point.
	 *
	 *       dentry->d_parent *is* stable here - it's an argument of ->lookup() and
	 *       we are guaranteed that it won't be moved anywhere until we feed it
	 *       to d_add.  So we safely go that way to get to its underlying dentry.
	 */
	fsstack_copy_attr_atime(d_inode(dentry->d_parent), d_inode(lower_dir_dentry));

	/* d_splice_alias() ensures that only one dentry is pointing to the inode,
	 * and returns the other dentry if one is found. It performs d_add() for the dentry.
	 *
	 * note: For directories there must never point two dentries to the same inode,
	 *       otherwise a deadlock can happen - especially when lock_rename() is
	 *       called in a rename operation.
	 *
	 * note: in linux-3.19 the remote rename support from d_materialise_unique()
	 *       was merged into d_splice_alias(). The old d_splice_alias() would
	 *       return EIO when an unhashed directory entry was found.
	 */
#ifdef NO_D_SPLICE_ALIAS_REMOTE_RENAME_SUPPORT
	ret_dentry = d_materialise_unique(dentry, inode); /* add positive dentry */
#else
	ret_dentry = d_splice_alias(inode, dentry); /* add positive dentry */
#endif
	if (ret_dentry) {
		if (IS_ERR(ret_dentry)) {
			pr_debug("wrapfs: lookup(%pd4) warn: splice error %d\n", dentry, (int)PTR_ERR(ret_dentry));
		}
	}
out:
	return ret_dentry;
}
