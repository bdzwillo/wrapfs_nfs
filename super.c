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

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *wrapfs_inode_cachep;

/* final actions when unmounting a file system */
static void wrapfs_put_super(struct super_block *sb)
{
	struct wrapfs_sb_info *spd;
	struct super_block *s;

	spd = WRAPFS_SB(sb);
	if (!spd)
		return;

	/* decrement lower super references */
	s = wrapfs_lower_super(sb);
	wrapfs_set_lower_super(sb, NULL);
	atomic_dec(&s->s_active);

	kfree(spd);
	sb->s_fs_info = NULL;
}

static int wrapfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;

	err = vfs_statfs(wrapfs_get_lower_path(dentry), buf);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = WRAPFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int wrapfs_remount_fs(struct super_block *sb, int *flags, char *options)
{
	int err = 0;

	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	if ((*flags & ~(SB_RDONLY | SB_MANDLOCK | SB_SILENT)) != 0) {
#else
	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
#endif
		printk(KERN_ERR
		       "wrapfs: remount flags 0x%x unsupported\n", *flags);
		err = -EINVAL;
	}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void wrapfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = wrapfs_lower_inode(inode);
	wrapfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *wrapfs_alloc_inode(struct super_block *sb)
{
	struct wrapfs_inode_info *i;

	i = kmem_cache_alloc(wrapfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct wrapfs_inode_info, vfs_inode));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
	atomic64_set(&i->vfs_inode.i_version, 1);
#else
	i->vfs_inode.i_version = 1;
#endif
	return &i->vfs_inode;
}

static void wrapfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(wrapfs_inode_cachep, WRAPFS_I(inode));
}

/* wrapfs inode cache constructor */
static void init_once(void *obj)
{
	struct wrapfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int wrapfs_init_inode_cache(void)
{
	int err = 0;

	wrapfs_inode_cachep =
		kmem_cache_create("wrapfs_inode_cache",
				  sizeof(struct wrapfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!wrapfs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* wrapfs inode cache destructor */
void wrapfs_destroy_inode_cache(void)
{
	if (wrapfs_inode_cachep)
		kmem_cache_destroy(wrapfs_inode_cachep);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void wrapfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = wrapfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

/* Prints the mount options for a given superblock.
 * Returns zero; does not fail.
 */
static int wrapfs_show_options(struct seq_file *m, struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct wrapfs_sb_info *spd;

	spd = WRAPFS_SB(sb);
	if (!spd) {
		return 0;
	}
	return 0;
}

const struct super_operations wrapfs_sops = {
	.put_super	= wrapfs_put_super,
	.statfs		= wrapfs_statfs,
	.remount_fs	= wrapfs_remount_fs,
	.evict_inode	= wrapfs_evict_inode,
	.umount_begin	= wrapfs_umount_begin,
	.show_options	= wrapfs_show_options,
	.alloc_inode	= wrapfs_alloc_inode,
	.destroy_inode	= wrapfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};

/* NFS support */

static struct inode *wrapfs_nfs_get_inode(struct super_block *sb, u64 ino,
					  u32 generation)
{
	struct super_block *lower_sb;
	struct inode *inode;
	struct inode *lower_inode;

	lower_sb = wrapfs_lower_super(sb);
	lower_inode = ilookup(lower_sb, ino);
	if (!lower_inode) {
		pr_err("wrapfs: exported ino %s:%llu not found\n", lower_sb->s_id, ino);
		return NULL; // d_obtain_alias() will return ERR_PTR(-ESTALE) for dentry
	}
	inode = wrapfs_iget(sb, lower_inode);
	return inode;
}

/* nfs fh mapping works only if the underlying filesystem uses
 * 32-bit filehandles compatible with the standard fid->i32 field.
 *
 * returns ESTALE if the inode is not found.
 */
static struct dentry *wrapfs_fh_to_dentry(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	pr_debug("wrapfs: fh_to_dentry fh_len %d fh_type %d\n", fh_len, fh_type);

	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    wrapfs_nfs_get_inode);
}

static struct dentry *wrapfs_fh_to_parent(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	pr_debug("wrapfs: fh_to_parent fh_len %d fh_type %d\n", fh_len, fh_type);

	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    wrapfs_nfs_get_inode);
}

/*
 * all other funcs are default as defined in exportfs/expfs.c
 */

const struct export_operations wrapfs_export_ops = {
	.fh_to_dentry	   = wrapfs_fh_to_dentry,
	.fh_to_parent	   = wrapfs_fh_to_parent
};
