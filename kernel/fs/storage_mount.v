// SPDX-License-Identifier: GPL-2.0-or-later
module fs

import errno

// Only direct managed endpoints may back a normal block-filesystem mount.
// Mapper directories and removable mknod wrappers remain forbidden, as do
// bind/move/cover operations. The caller reserves the extent under vfs_lock
// before releasing the name, then keeps that reservation through probing.
fn volume_filesystem_source(node &VFSNode, kind string) bool {
	if node == unsafe { nil } || node.resource == unsafe { nil } { return false }
	return (kind == 'ext2' || kind == 'ext4') && node.resource is LogicalVolume
}

fn begin_volume_filesystem_mount(node &VFSNode, kind string) ?int {
	if !volume_filesystem_source(node, kind) { errno.set(errno.ebusy); return none }
	token := begin_block_device_mount(node)?
	// A concurrently removed managed endpoint reports a zero identity. Unlike
	// an insecure RAM block inode, it must never proceed with token -1.
	if token < 0 { errno.set(errno.enodev); return none }
	return token
}
