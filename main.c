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
#include <linux/module.h>
#include <linux/parser.h>

#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
struct wrapfs_mountopt {
	bool block;
	int uid;
	const char *lower_path_name;
};

enum { Opt_block, Opt_uid, Opt_err };

static match_table_t tokens = {
	{Opt_block, "block"},
	{Opt_uid, "uid=%u"},
	{Opt_err, NULL}
};

static int parse_options(char *options, struct wrapfs_mountopt *opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];

	/* defaults */
	memset(opts, 0, sizeof(*opts));

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_block:
			opts->block = true;
			break;
		case Opt_uid:
			if (match_int(&args[0], &opts->uid)) {
				return -EINVAL;
			}
			break;
		}
	}
	return 0;
}
#endif

/*
 * There is no need to lock the wrapfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int wrapfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY) 
	struct wrapfs_mountopt *opts = raw_data;
	char *dev_name = (char *)opts->lower_path_name;
#else
	char *dev_name = (char *) raw_data;
#endif
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "wrapfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"wrapfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct wrapfs_sb_info), GFP_KERNEL);
	if (!WRAPFS_SB(sb)) {
		printk(KERN_CRIT "wrapfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	wrapfs_set_lower_super(sb, lower_sb);
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY) 
	WRAPFS_SB(sb)->rdonly = opts->block;
	WRAPFS_SB(sb)->single_uid = opts->uid;
#endif
	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &wrapfs_sops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	sb->s_xattr = wrapfs_xattr_handlers;
#endif
	sb->s_export_op = &wrapfs_export_ops; /* adding NFS support */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
	if (lower_sb->s_flags & MS_NOREMOTELOCK) {
		sb->s_flags |= MS_NOREMOTELOCK; /* set this to use local file locks instead of nfs locks */
	}
#endif
	sb->s_d_op = &wrapfs_dops;

	/* get a new inode and allocate our root dentry */
	inode = wrapfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		// d_make_root() calls iput(inode) on error
		err = -ENOMEM;
		goto out_sput;
	}
	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = wrapfs_new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	wrapfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "wrapfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: wrapfs_free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
	sb->s_root = NULL;
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(WRAPFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

struct dentry *wrapfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
#if defined(WRAPFS_INTERCEPT_INODE_MODIFY)
        int ret;
	struct wrapfs_mountopt opts;

	ret = parse_options(raw_data, &opts);
        if (ret)
                return ERR_PTR(ret);

        opts.lower_path_name = dev_name;

	return mount_nodev(fs_type, flags, &opts, wrapfs_read_super);
#else
	void *lower_path_name = (void *) dev_name;

	return mount_nodev(fs_type, flags, lower_path_name,
		wrapfs_read_super);
#endif
}

static void wrapfs_kill_super_block(struct super_block *sb)
{
	kill_anon_super(sb); // calls generic_shutdown_super()->re_put_super() where s_fs_info is freed
}

static struct file_system_type wrapfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= WRAPFS_NAME,
	.mount		= wrapfs_mount,
	.kill_sb	= wrapfs_kill_super_block,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(WRAPFS_NAME);

static int __init init_wrapfs_fs(void)
{
	int err;

	pr_info("Registering wrapfs " WRAPFS_VERSION "\n");

	err = wrapfs_init_inode_cache();
	if (err)
		goto out;
	err = wrapfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&wrapfs_fs_type);
out:
	if (err) {
		wrapfs_destroy_inode_cache();
		wrapfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_wrapfs_fs(void)
{
	wrapfs_destroy_inode_cache();
	wrapfs_destroy_dentry_cache();
	unregister_filesystem(&wrapfs_fs_type);
	pr_info("Completed wrapfs module unload\n");
}

MODULE_AUTHOR("Original Wrapfs from Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
 	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("wrapfs_nfs " WRAPFS_VERSION 
                   " (based on Wrapfs from http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_wrapfs_fs);
module_exit(exit_wrapfs_fs);
