/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <linux/vmalloc.h>
#include <asm/mman.h>
#include "pmfs.h"
#include "xip.h"

static inline int pmfs_can_set_blocksize_hint(struct pmfs_inode *pi,
					       loff_t new_size)
{
	/* Currently, we don't deallocate data blocks till the file is deleted.
	 * So no changing blocksize hints once allocation is done. */
	if (le64_to_cpu(pi->root))
		return 0;
	return 1;
}

int pmfs_set_blocksize_hint(struct super_block *sb, struct pmfs_inode *pi,
		loff_t new_size)
{
	unsigned short block_type;

	if (!pmfs_can_set_blocksize_hint(pi, new_size))
		return 0;

	if (new_size >= 0x40000000) {   /* 1G */
		block_type = PMFS_BLOCK_TYPE_1G;
		goto hint_set;
	}

	if (new_size >= 0x200000) {     /* 2M */
		block_type = PMFS_BLOCK_TYPE_2M;
		goto hint_set;
	}

	/* defaulting to 4K */
	block_type = PMFS_BLOCK_TYPE_4K;

hint_set:
	pmfs_dbg_verbose(
		"Hint: new_size 0x%llx, i_size 0x%llx, root 0x%llx\n",
		new_size, pi->i_size, le64_to_cpu(pi->root));
	pmfs_dbg_verbose("Setting the hint to 0x%x\n", block_type);
	pmfs_memunlock_inode(sb, pi);
	PM_EQU(pi->i_blk_type, block_type);
	pmfs_memlock_inode(sb, pi);
	return 0;
}

static long pmfs_fallocate(struct file *file, int mode, loff_t offset,
			    loff_t len)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	long ret = 0;
	unsigned long blocknr, blockoff;
	int num_blocks, blocksize_mask;
	struct pmfs_inode *pi;
	pmfs_transaction_t *trans;
	loff_t new_size;

	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	mutex_lock(&inode->i_mutex);

	new_size = len + offset;
	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out;
	}

	pi = pmfs_get_inode(sb, inode->i_ino);
	if (!pi) {
		ret = -EACCES;
		goto out;
	}
	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES +
			MAX_METABLOCK_LENTRIES);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}
	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	/* Set the block size hint */
	pmfs_set_blocksize_hint(sb, pi, new_size);

	blocksize_mask = sb->s_blocksize - 1;
	blocknr = offset >> sb->s_blocksize_bits;
	blockoff = offset & blocksize_mask;
	num_blocks = (blockoff + len + blocksize_mask) >> sb->s_blocksize_bits;
	ret = pmfs_alloc_blocks(trans, inode, blocknr, num_blocks, true);

	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;

	pmfs_memunlock_inode(sb, pi);
	if (ret || (mode & FALLOC_FL_KEEP_SIZE)) {
		PM_OR_EQU(pi->i_flags, cpu_to_le32(PMFS_EOFBLOCKS_FL));
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		inode->i_size = new_size;
		PM_EQU(pi->i_size, cpu_to_le64(inode->i_size));
	}
	PM_EQU(pi->i_mtime, cpu_to_le32(inode->i_mtime.tv_sec));
	PM_EQU(pi->i_ctime, cpu_to_le32(inode->i_ctime.tv_sec));
	pmfs_memlock_inode(sb, pi);

	pmfs_commit_transaction(sb, trans);

out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

static loff_t pmfs_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	mutex_lock(&inode->i_mutex);
	switch (origin) {
	case SEEK_DATA:
		retval = pmfs_find_region(inode, &offset, 0);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			return retval;
		}
		break;
	case SEEK_HOLE:
		retval = pmfs_find_region(inode, &offset, 1);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			return retval;
		}
		break;
	}

	if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	    offset > inode->i_sb->s_maxbytes) {
		mutex_unlock(&inode->i_mutex);
		return -EINVAL;
	}

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	mutex_unlock(&inode->i_mutex);
	return offset;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling pmfs_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * pmfs_flush_buffer() on fsync() */
int pmfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	loff_t isize;
	timing_t fsync_time;

	PMFS_START_TIMING(fsync_t, fsync_time);
	/* if the file is not mmap'ed, there is no need to do clflushes */
	if (mapping_mapped(mapping) == 0)
		goto persist;

	end += 1; /* end is inclusive. We like our indices normal please ! */

	isize = i_size_read(inode);

	if ((unsigned long)end > (unsigned long)isize)
		end = isize;
	if (!isize || (start >= end))
	{
		pmfs_dbg_verbose("[%s:%d] : (ERR) isize(%llx), start(%llx),"
			" end(%llx)\n", __func__, __LINE__, isize, start, end);
		PMFS_END_TIMING(fsync_t, fsync_time);
		return -ENODATA;
	}

	/* Align start and end to cacheline boundaries */
	start = start & CACHELINE_MASK;
	end = CACHELINE_ALIGN(end);
	do {
		sector_t block = 0;
		void *xip_mem;
		pgoff_t pgoff;
		loff_t offset;
		unsigned long nr_flush_bytes;

		pgoff = start >> PAGE_CACHE_SHIFT;
		offset = start & ~PAGE_CACHE_MASK;

		nr_flush_bytes = PAGE_CACHE_SIZE - offset;
		if (nr_flush_bytes > (end - start))
			nr_flush_bytes = end - start;

		block = pmfs_find_data_block(inode, (sector_t)pgoff);

		if (block) {
			xip_mem = pmfs_get_block(inode->i_sb, block);
			/* flush the range */
			atomic64_inc(&fsync_pages);
			pmfs_flush_buffer(xip_mem + offset, nr_flush_bytes, 0);
		} else {
			/* sparse files could have such holes */
			pmfs_dbg_verbose("[%s:%d] : start(%llx), end(%llx),"
			" pgoff(%lx)\n", __func__, __LINE__, start, end, pgoff);
			break;
		}

		start += nr_flush_bytes;
	} while (start < end);
persist:
	PERSISTENT_MARK();
	// PERSISTENT_BARRIER(); /* not required, usercode is responsible */
	PMFS_END_TIMING(fsync_t, fsync_time);
	return 0;
}

/* This callback is called when a file is closed */
static int pmfs_flush(struct file *file, fl_owner_t id)
{
	int ret = 0;


	/* if the file was opened for writing, make it persistent.
	 * TODO: Should we be more smart to check if the file was modified? */
	if (file->f_mode & FMODE_WRITE) {
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}

	return ret;
}

static int pmfs_file_release(struct inode *inode, struct file *file)
{
	struct pmfs_inode_info *pi_info = PMFS_I(inode);
	if (pi_info->i_virt_addr) {
//		printk("In %s, free va:0x%lx\n", __FUNCTION__, (unsigned long)pi_info->i_virt_addr);
		vfree(pi_info->i_pfns);
		vfree(pi_info->ptes);
		free_vm_area(pi_info->area);
		pi_info->i_virt_addr = NULL;
	}

	return 0;
}

inline  unsigned long  NUM_PAGES(unsigned long t)
{
	return (t >> 12) + (t % 4096 > 0 ? 1 : 0);
}

static int pmfs_malloc_va(size_t desired_size, struct inode *inode)
{
	struct pmfs_inode_info *pi_info = PMFS_I(inode);
//	printk("In %s, required entry size=%lu\n", __FUNCTION__, (PAGE_ALIGN(desired_size) >> 12));
	pi_info->i_pfns = (unsigned long *)vmalloc(sizeof(unsigned long) * (PAGE_ALIGN(desired_size) >> 12));
	pi_info->ptes = (pte_t **)vmalloc(sizeof(pte_t *) * (PAGE_ALIGN(desired_size) >> 12));
	pi_info->area = alloc_vm_area(PAGE_ALIGN(desired_size), pi_info->ptes);
	if (pi_info->area) {
		pi_info->i_virt_addr = pi_info->area->addr;
//		printk("The allocated addr=0x%lx\n", (unsigned long)pi_info->i_virt_addr);
		return 0;
	}

	return 1;
}

static int pmfs_file_open(struct inode *inode, struct file *filep)
{
	struct pmfs_inode_info *pi_info;
	unsigned long size = 0;
	char *p;
	unsigned long i = 0;
	unsigned long desired_size = 0;

	pi_info = PMFS_I(inode);
	pi_info->i_pfns = NULL;
	pi_info->i_virt_addr = NULL;
	pi_info->ptes = NULL;
	pi_info->area = NULL;
	pi_info->num_pfns_mapped_in_va = 0;

	size = i_size_read(inode);
	/*We double the space requirement for the existing file size*/
	desired_size = i_size_read(inode) * 2;
	if (size > PMFS_FILE_SIZE_THRESHOLD && !pi_info->i_virt_addr) {
		if (pmfs_malloc_va(desired_size, inode)) {
			printk("In %s, malloc va failed\n", __FUNCTION__);
		}
		pmfs_get_file_pfns(inode);
		pmfs_map_va(inode);
		//p = (char *)pi_info->i_virt_addr;
		//printk("The file content:\n");
		//for (i = 0; i < size;i++) {
		//	printk("%c", p[i]+1);
		//}
	}

	return generic_file_open(inode, filep);
}

const struct file_operations pmfs_xip_file_operations = {
	.llseek = pmfs_llseek,
	.read = pmfs_xip_file_read,
	.write = pmfs_xip_file_write,
	//	Pre 4.x.x era
	//	Either implement these or let user-apps know
	//	that this is unimplemented. For eg., MySQL needs aio.
	//	.aio_read		= xip_file_aio_read,
	//	.aio_write		= xip_file_aio_write,
	//	For 4.x and above but troubles NFS or anyone who uses thes *iter fn
	//	.read_iter		= generic_file_read_iter,
	//	.write_iter		= generic_file_write_iter,
		.mmap = pmfs_xip_file_mmap,
		// 	Can we avoid VFS if we don't call into generic_* routines ?
			//.open			= generic_file_open,
			.open = pmfs_file_open,
			.fsync = pmfs_fsync,
			.flush = pmfs_flush,
		.release = pmfs_file_release,
//	.get_unmapped_area	= pmfs_get_unmapped_area,
	.unlocked_ioctl		= pmfs_ioctl,
	.fallocate		= pmfs_fallocate,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= pmfs_compat_ioctl,
#endif
};

const struct inode_operations pmfs_file_inode_operations = {
	.setattr	= pmfs_notify_change,
	.getattr	= pmfs_getattr,
	.get_acl	= NULL,
};
