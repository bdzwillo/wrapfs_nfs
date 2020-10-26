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

struct inode *wrapfs_iget(struct super_block *sb, struct inode *lower_inode)
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

	inode->i_version++;

	/* use different set of inode ops for symlinks & directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &wrapfs_dir_iops;
	else if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &wrapfs_symlink_iops;
	else
		inode->i_op = &wrapfs_main_iops;

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

	unlock_new_inode(inode);
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
	inode = wrapfs_iget(sb, lower_inode);
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
		     struct path *lower_path)
{
	struct inode *inode;
	struct inode *lower_inode = lower_path->dentry->d_inode;

	inode = wrapfs_get_inode(dentry, sb, lower_inode);
	if (IS_ERR(inode)) {
		return PTR_ERR(inode);
	}
	d_instantiate(dentry, inode);
	return 0;
}

/*
 * wrapfs lookup
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred.
 * Fills in positive/negative dentry->d_inode on success.
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
	lower_dir_mnt	 = wrapfs_get_lower_path_nolock(dentry->d_parent)->mnt;

	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
 	lower_dentry = lookup_one_len(dentry->d_name.name, lower_dir_dentry, dentry->d_name.len);
 	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		pr_debug("wrapfs: lookup(%pd4, 0x%x) -> err %d\n", dentry, flags, (int)PTR_ERR(lower_dentry));
		ret_dentry = lower_dentry;
		goto out;
	}

	/* LOOKUP_ flags are defined in include/linux/namei_lookup.h
	 */
	pr_debug("wrapfs: lookup(%pd4, 0x%x) inode %s:%lu\n", dentry, flags, lower_dentry->d_inode ? lower_dentry->d_inode->i_sb->s_id : "NULL", lower_dentry->d_inode ? lower_dentry->d_inode->i_ino : 0);

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

	lower_inode = lower_dentry->d_inode;
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
	d_add(dentry, inode); /* add positive dentry */

	/* update parent directory's atime */
	fsstack_copy_attr_atime(dentry->d_parent->d_inode, wrapfs_lower_inode(dentry->d_parent->d_inode));
out:
	/* if a real dentry is returned here, dput() will be called on it.
	 * if NULL is returned positive/negative dentry from params will be used without dput().
	 */
	return ret_dentry;
}
