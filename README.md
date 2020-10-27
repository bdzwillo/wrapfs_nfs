wrapfs_nfs
==========
This wrapfs version is based on the original wrapfs from https://wrapfs.filesystems.org/
and supports operation as a loopback filesystem on top of an underlying nfs mount.

- this was implemented for a project with the requirement for a loadable vfs-module 
  running on centos/redhat-7 servers.

- it was choosen to base the vfs on wrapfs, since there is no simple in-tree
  implementation of a loopback filesystem, and some other vfs implementations
  like ecryptfs and overlayfs seem to originate from wrapfs.

- since the original wrapfs does only support the vanilla kernel, it needed some
  adjustments to compile on centos. For the linux-3.10.0-1127.10.1.el7 kernel the best
  match was wrapfs-v3.15.10-96 from http://download.filesystems.org/wrapfs/patches/.

- this wrapfs version fixes some bugs when mounted on top of a remote filesystem.
  It also includes some simplifications for the lookup-, locking- & mmap-code based 
  on the ecryptfs & overlayfs kernel modules.

Debugging
---------
Show all available pr_debug() calls:

```# grep wrapfs /sys/kernel/debug/dynamic_debug/control```

Enable output for all pr_debug() calls:

```# echo "file */wrapfs/* +p" > /sys/kernel/debug/dynamic_debug/control```

Intercept Example
-----------------
The branch **intercept_modify** includes example code which shows how to intercept all inode
write operations (in our project this is used to implement path based security rules).

- the interception code is enabled via -DWRAPFS_INTERCEPT_INODE_MODIFY

The example code can be used to deny write access for a single uid. The usage is like follows:
```
# insmod wrapfs.ko
# mount -t wrapfs -o block,uid=12345 /mnt/test /mnt/test
```
