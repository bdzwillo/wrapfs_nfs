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

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry (calls d_invalidate(dentry) there)
 *          1: dentry is valid
 */
static int wrapfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *lower_dentry;
	int ret = 1;

	/* If in rcu-walk mode, the filesystem must revalidate the dentry without
	 * blocking or storing to the dentry, d_parent and d_inode should not be
	 * used without care (because they can change and, in d_inode case, even
	 * become NULL under us)
	 * 
	 * This might even be the case for wrapfs_get_lower_dentry() where
	 * dentry->d_fsdata can be NULL here.
	 */
	if (flags & LOOKUP_RCU) {
		return -ECHILD; // call d_revalidate() again in ref-walk-mode
	}
	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!(lower_dentry->d_flags & DCACHE_OP_REVALIDATE))
		goto out;
	ret = lower_dentry->d_op->d_revalidate(lower_dentry, flags);

	pr_debug("wrapfs: revalidate(%pd4, 0x%04x) = %d", dentry, flags, ret);

	if (ret < 0) {
		goto out; // might also be ECHILD to call revalidate again
	}
out:
	return ret;
}

/*
 * weak_revalidate is called for result of path lookup (namei:complete_walk())
 * 0: returns ESTALE there
 * 1: dentry is valid
 */
static int wrapfs_d_weak_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *lower_dentry;
	int ret = 1;

	lower_dentry = wrapfs_get_lower_dentry(dentry);
	if (!(lower_dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE))
		goto out;
	ret = lower_dentry->d_op->d_weak_revalidate(lower_dentry, flags);

	pr_debug("wrapfs: weak_revalidate(%pd4, 0x%04x) = %d", dentry, flags, ret);
out:
	return ret;
}

static void wrapfs_d_release(struct dentry *dentry)
{
	/* release and reset the lower paths */
	if (WRAPFS_D(dentry)) {
		if (wrapfs_get_lower_dentry(dentry)) {
			wrapfs_put_reset_lower_path(dentry);
		}
		wrapfs_free_dentry_private_data(dentry);
	}
	return;
}

const struct dentry_operations wrapfs_dops = {
	.d_revalidate	= wrapfs_d_revalidate,
	.d_release	= wrapfs_d_release,
	.d_weak_revalidate = wrapfs_d_weak_revalidate,
};
