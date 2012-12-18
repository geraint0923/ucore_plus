#include <types.h>
#include <string.h>
#include <slab.h>
#include <vfs.h>
#include <proc.h>
#include <file.h>
#include <unistd.h>
#include <iobuf.h>
#include <inode.h>
#include <stat.h>
#include <dirent.h>
#include <error.h>
#include <assert.h>

#include <vmm.h>

#define testfd(fd)		((fd) >= 0 && (fd) < FS_STRUCT_NENTRY)

/*
static void remove_mapped_vma(struct vma_struct *vma) {
	if(vma->vm_file) {
		filemap_release(vma->vm_file);
	}
}

static struct vma_struct *
find_vma_prepare(struct mm_struct *mm, unsigned long addr, 
		struct vma_struct **pprev) {
	struct vma_struct *vma = NULL;

	// assume not using rb_tree

	list_entry_t *list = &(mm->mmap_list), *le = list, *prevle = NULL;
	while((le = list_next(le))  != list) {
		struct vma_struct *vma_tmp;

		vma_tmp = le2vma(le, list_link);
		if(vma_tmp->vm_end > addr) {
			vma = vma_tmp;
			if(vma_tmp->vm_start <= addr)
				break;
		} else {
			prevle = le;
		}
	}
	
	*pprev = NULL;
	if(prevle) {
		*pprev = le2vma(prevle, list_link);
	}

	return vma;
}

unsigned long mmap_region(struct file *file, unsigned long addr,
		unsigned long len, unsigned long flags,
		uint32_t vm_flags, unsigned long pgoff) {

	struct mm_struct *mm = pls_read(current)->mm;
	struct vma_struct *vma, *prev;
	int correct_wcount = 0;
	int error;
	unsigned long charged = 0;
	// struct inode *inode =  file ? file->f_path.dentry->d_inode : NULL;
	error = -ENOMEM;

munmap_back:
	vma = find_vma_prepare(mm, addr, &prev);
	if(vma && vma->vm_start < addr + len) {
		if(do_munmap(mm, addr, len)) {
			return -ENOMEM;
		}
		goto mumap_back;
	}

	vma_merge(mm, prev, addr, addr + len, vm_flags, NULL, file, pgoff, NULL);
	if(vma) {
		goto out;
	}

	if(!vma) {
		error = -ENOMEM;
		goto unacct_error;
	}

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
//	vma->vm_page_prot = vm_get_page_prot(vm_flags);
	vma->vm_pgoff = pgoff;

	if(file) {
		error = -EINVAL;
		vma->vm_file = file;
		filemap_acquire(file);
		error = vop_mmap(file->node, file, vma);
		if(error)
			goto unmap_and_free_vma;
		addr = vma->vm_start;
		pgoff = vma->vm_pgoff;
		vm_flags = vma->vm_flags;
	} else if(vm_flags & VM_SHARED) {
		kprintf("VM_SHARE! in mmap_region\n");
	}

	vma_link(mm, vma, prev);
	file = vma->vm_file;

out:
	perf_event_mmap(vma);

	return addr;

unmap_and_free_vma:
	vma->vm_file = NULL;
	filemap_release(file);

	unmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);

free_vma:
	free(vma);

	return error;

	return NULL;
}
*/
