/* binder.c
 *
 * Android IPC Subsystem
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <types.h>
#include <stdio.h>
#include <wait.h>
#include <sync.h>
#include <proc.h>
#include <sched.h>
#include <dev.h>
#include <vfs.h>
#include <iobuf.h>
#include <inode.h>
#include <unistd.h>
#include <error.h>
#include <assert.h>
#include <sem.h>
#include <rb_tree.h>

#include "binder.h"

// replace mutex by sem
static semaphore_t binder_main_lock;
static semaphore_t binder_deferred_lock;
static semaphore_t binder_mmap_lock;

// replace hlist by list
static list_entry_t binder_procs;
static list_entry_t binder_deferred_list;
static list_entry_t binder_dead_nodes;

// replace uid_t by uint32_t
static struct binder_node *binder_context_mgr_node;
static uint32_t binder_context_mgr_uid = -1;
static int binder_last_id;

// TODO: WORKQUEUE
//static struct workqueue_struct *binder_deferred_workqueue;

// FIXME:
static struct file* binder_filp;

// glue:
#define __user
#define KERN_INFO "[Info] "
#define KERN_ERR  "[Err] "

#define rb_entry to_struct
#define list_entry to_struct
#define container_of to_struct

// glue:
#define PGSHIFT 12
#define PGSIZE 4096
#define PGMASK 4095

static uint32_t kzalloc(size_t n)
{
    uint32_t mem = kmalloc(n);
    if (!mem)
        return mem;
    memset((void*)mem, 0, n);
    return mem;
}

// TODO:
static int task_nice(const struct proc_struct* task)
{
    return 1;
}


/* This is only defined in include/asm-arm/sizes.h */
#ifndef SZ_1K
#define SZ_1K                               0x400
#endif

#ifndef SZ_4M
#define SZ_4M                               0x400000
#endif

#define FORBIDDEN_MMAP_FLAGS                (VM_WRITE)

#define BINDER_SMALL_BUF_SIZE (PGSIZE * 64)

enum {
	BINDER_DEBUG_USER_ERROR             = 1U << 0,
	BINDER_DEBUG_FAILED_TRANSACTION     = 1U << 1,
	BINDER_DEBUG_DEAD_TRANSACTION       = 1U << 2,
	BINDER_DEBUG_OPEN_CLOSE             = 1U << 3,
	BINDER_DEBUG_DEAD_BINDER            = 1U << 4,
	BINDER_DEBUG_DEATH_NOTIFICATION     = 1U << 5,
	BINDER_DEBUG_READ_WRITE             = 1U << 6,
	BINDER_DEBUG_USER_REFS              = 1U << 7,
	BINDER_DEBUG_THREADS                = 1U << 8,
	BINDER_DEBUG_TRANSACTION            = 1U << 9,
	BINDER_DEBUG_TRANSACTION_COMPLETE   = 1U << 10,
	BINDER_DEBUG_FREE_BUFFER            = 1U << 11,
	BINDER_DEBUG_INTERNAL_REFS          = 1U << 12,
	BINDER_DEBUG_BUFFER_ALLOC           = 1U << 13,
	BINDER_DEBUG_PRIORITY_CAP           = 1U << 14,
	BINDER_DEBUG_BUFFER_ALLOC_ASYNC     = 1U << 15,
};
static uint32_t binder_debug_mask = BINDER_DEBUG_USER_ERROR |
	BINDER_DEBUG_FAILED_TRANSACTION | BINDER_DEBUG_DEAD_TRANSACTION;

static bool binder_debug_no_lock;

// replace by wait_queue
static wait_queue_t binder_user_error_wait;
static int binder_stop_on_user_error;


#define binder_debug(mask, x...) \
	do { \
		if (binder_debug_mask & mask) \
			cprintf(KERN_INFO x); \
	} while (0)

#define binder_user_error(x...) \
	do { \
		if (binder_debug_mask & BINDER_DEBUG_USER_ERROR) \
			cprintf(KERN_INFO x); \
		if (binder_stop_on_user_error) \
			binder_stop_on_user_error = 2; \
	} while (0)

enum binder_stat_types {
	BINDER_STAT_PROC,
	BINDER_STAT_THREAD,
	BINDER_STAT_NODE,
	BINDER_STAT_REF,
	BINDER_STAT_DEATH,
	BINDER_STAT_TRANSACTION,
	BINDER_STAT_TRANSACTION_COMPLETE,
	BINDER_STAT_COUNT
};


struct binder_transaction_log_entry {
	int debug_id;
	int call_type;
	int from_proc;
	int from_thread;
	int target_handle;
	int to_proc;
	int to_thread;
	int to_node;
	int data_size;
	int offsets_size;
};
struct binder_transaction_log {
	int next;
	int full;
	struct binder_transaction_log_entry entry[32];
};
static struct binder_transaction_log binder_transaction_log;
static struct binder_transaction_log binder_transaction_log_failed;

// glue ARR_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static struct binder_transaction_log_entry *binder_transaction_log_add(struct binder_transaction_log *log)
{
	struct binder_transaction_log_entry *e;
	e = &log->entry[log->next];
	memset(e, 0, sizeof(*e));
	log->next++;
	if (log->next == ARRAY_SIZE(log->entry)) {
		log->next = 0;
		log->full = 1;
	}
	return e;
}

struct binder_work {
	list_entry_t entry;
	enum {
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	} type;
};

// replace rb_node & hlist
struct binder_node {
	int debug_id;
	struct binder_work work;
	union {
		rb_node rb_node;
		list_entry_t dead_node;
	};
	struct binder_proc *proc;
	list_entry_t refs;
	int internal_strong_refs;
	int local_weak_refs;
	int local_strong_refs;
	void *ptr;
	void *cookie; // __user
	unsigned has_strong_ref:1;
	unsigned pending_strong_ref:1;
	unsigned has_weak_ref:1;
	unsigned pending_weak_ref:1;
	unsigned has_async_transaction:1;
	unsigned accept_fds:1;
	unsigned min_priority:8;
	list_entry_t async_todo;
};

struct binder_ref_death {
	struct binder_work work;
	void *cookie;
};

struct binder_ref {
	/* Lookups needed: */
	/*   node + proc => ref (transaction) */
	/*   desc + proc => ref (transaction, inc/dec ref) */
	/*   node => refs + procs (proc exit) */
	int debug_id;
	rb_node rb_node_desc;
	rb_node rb_node_node;
	list_entry_t node_entry;
	struct binder_proc *proc;
	struct binder_node *node;
	uint32_t desc;
	int strong;
	int weak;
	struct binder_ref_death *death;
};

struct binder_buffer {
	list_entry_t entry; /* free and allocated entries by address */
	rb_node rb_node; /* free entry by size or allocated entry */
				/* by address */
	unsigned free:1;
	unsigned allow_user_free:1;
	unsigned async_transaction:1;
	unsigned debug_id:29;

	struct binder_transaction *transaction;

	struct binder_node *target_node;
	size_t data_size;
	size_t offsets_size;
	uint8_t data[0];
};

enum binder_deferred_state {
	BINDER_DEFERRED_PUT_FILES    = 0x01,
	BINDER_DEFERRED_FLUSH        = 0x02,
	BINDER_DEFERRED_RELEASE      = 0x04,
};

struct binder_proc {
	list_entry_t proc_node;
	rb_tree* threads;
	rb_tree* nodes;
	rb_tree* refs_by_desc;
	rb_tree* refs_by_node;
	int pid;
	// replace vm_area_struct by vma_struct
	struct vma_struct *vma;
	struct mm_struct *vma_vm_mm;
	struct proc_struct *tsk;
	struct fs_struct *files;
	list_entry_t deferred_work_node;
	int deferred_work;
	void *buffer;
	// replace ptrdiff_t by int
	int user_buffer_offset;
	// FIXME: temperaraly record kernel space base
	struct Page* page_area;

	list_entry_t buffers;
	rb_tree* free_buffers;
	rb_tree* allocated_buffers;
	size_t free_async_space;
    // TODO: page??? is it OK
	struct Page **pages;
	size_t buffer_size;
	uint32_t buffer_free;
	list_entry_t todo;
	wait_queue_t wait;
	list_entry_t delivered_death;
	int max_threads;
	int requested_threads;
	int requested_threads_started;
	int ready_threads;
	long default_priority;
};

enum {
	BINDER_LOOPER_STATE_REGISTERED  = 0x01,
	BINDER_LOOPER_STATE_ENTERED     = 0x02,
	BINDER_LOOPER_STATE_EXITED      = 0x04,
	BINDER_LOOPER_STATE_INVALID     = 0x08,
	BINDER_LOOPER_STATE_WAITING     = 0x10,
	BINDER_LOOPER_STATE_NEED_RETURN = 0x20
};

struct binder_thread {
	struct binder_proc *proc;
	rb_node rb_node_;
	int pid;
	int looper;
	struct binder_transaction *transaction_stack;
	list_entry_t todo;
	uint32_t return_error; /* Write failed, return error code in read buf */
	uint32_t return_error2; /* Write failed, return error code in read */
		/* buffer. Used when sending a reply to a dead process that */
		/* we are also waiting on */
	wait_queue_t wait;
};

struct binder_transaction {
	int debug_id;
	struct binder_work work;
	struct binder_thread *from;
	struct binder_transaction *from_parent;
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	struct binder_transaction *to_parent;
	unsigned need_reply:1;
	/* unsigned is_dead:1; */	/* not used at the moment */

	struct binder_buffer *buffer;
	unsigned int	code;
	unsigned int	flags;
	long	priority;
	long	saved_priority;
	/*uid_t*/
	uint32_t	sender_euid;
};

static void
binder_defer_work(struct binder_proc *proc, enum binder_deferred_state defer);

/*
 * copied from get_unused_fd_flags
 */
/// MayClear
int task_get_unused_fd_flags(struct binder_proc *proc);//, int flags)
{
	struct file *file_store;
	filemap_alloc(NO_FD, &file_store);
	return file_store ? file_store->fd : NO_FD;
	
//	struct fs_struct *files = proc->files;
//	int fd, error;
//	struct file** fdt;
//	unsigned long rlim_cur;
//	unsigned long irqs;

//	if (files == NULL)
//		return -ESRCH;

//	error = -EMFILE;
//	lock_fs(files);

//repeat:
//	fdt = files->filemap;
//	fd = find_next_zero_bit(fdt->open_fds, fdt->max_fds, files->next_fd);

	// FIXME:
	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
//	rlim_cur = 0;
//	if (lock_task_sighand(proc->tsk, &irqs)) {
//		rlim_cur = proc->tsk->signal->rlim[RLIMIT_NOFILE].rlim_cur;
//		unlock_task_sighand(proc->tsk, &irqs);
//	}
//	if (fd >= rlim_cur)
//		goto out;

	// FIXME:
	/* Do we need to expand the fd array or fd set?  */
//	error = expand_files(files, fd);
//	if (error < 0)
//		goto out;

//	if (error) {
		/*
		 * If we needed to expand the fs array we
		 * might have blocked - try again.
		 */
//		error = -EMFILE;
//		goto repeat;
//	}

//	__set_open_fd(fd, fdt);
//	if (flags & O_CLOEXEC)
//		__set_close_on_exec(fd, fdt);
//	else
//		__clear_close_on_exec(fd, fdt);
//	files->next_fd = fd + 1;

	/* Sanity check */
//	if (fdt->fd[fd] != NULL) {
//		cprintf(KERN_WARNING "get_unused_fd: slot %d not NULL!\n", fd);
//		fdt->fd[fd] = NULL;
//	}

//	error = fd;

//out:
//	spin_unlock(&files->file_lock);
//	return error;
}

/*
 * copied from fd_install
 */
/// MayClear
static void task_fd_install(struct binder_proc *proc, unsigned int fd, struct file *file)
{
	struct fs_struct* files = proc->files;
	struct file** fdt;

	if (files == NULL)
		return;

	lock_fs(files);
	fdt = files->filemap;
//	BUG_ON(fdt->fd[fd] != NULL);
//	rcu_assign_pointer(fdt->fd[fd], file);
	
	// UnClear; TODO: verify
	fdt[fd] = file;
	unlock_fsk(files);
}

/*
 * copied from sys_close
 */
/// MayClear
static long task_close_fd(struct binder_proc *proc, unsigned int fd)
{	
	struct fs_struct *files = proc->files;
	
	struct file* file = files->filemap[fd];
	filemap_close(file);	
        return 0;
	
//	struct file *filp;
//	struct fdtable *fdt;
//	int retval;

//	if (files == NULL)
//		return -ESRCH;

//	spin_lock(&files->file_lock);
//	fdt = files_fdtable(files);
//	if (fd >= fdt->max_fds)
//		goto out_unlock;
//	filp = fdt->fd[fd];
//	if (!filp)
//		goto out_unlock;
//	rcu_assign_pointer(fdt->fd[fd], NULL);
//	__clear_close_on_exec(fd, fdt);
//	__put_unused_fd(files, fd);
//	spin_unlock(&files->file_lock);
//	retval = filp_close(filp, files);
//
//	/* can't restart close syscall because file table entry was cleared */
//	if (retval == -ERESTARTSYS ||
//		     retval == -ERESTARTNOINTR ||
//		     retval == -ERESTARTNOHAND ||
//		     retval == -ERESTART_RESTARTBLOCK)
//		retval = -EINTR;

//	return retval;

//out_unlock:
//	spin_unlock(&files->file_lock);
//	return -EBADF;
}

static inline void binder_lock()
{
	down(&binder_main_lock);
}

static inline void binder_unlock()
{
	up(&binder_main_lock);
}

/// CLEAR
static void binder_set_nice(long nice)
{
    // TODO:
    return;
//	long min_nice;
//	if (can_nice(current, nice)) {
//		set_user_nice(current, nice);
//		return;
//	}
//	min_nice = 20 - current->signal->rlim[RLIMIT_NICE].rlim_cur;
//	binder_debug(BINDER_DEBUG_PRIORITY_CAP, "binder: %d: nice value %ld not allowed use %ld instead\n", current->pid, nice, min_nice);
//	set_user_nice(current, min_nice);
//	if (min_nice < 20)
//		return;
//	binder_user_error("binder: %d RLIMIT_NICE not set\n", current->pid);
}

/// CLEAR
static size_t binder_buffer_size(struct binder_proc *proc, struct binder_buffer *buffer)
{
	if (list_next(&buffer->entry) == &proc->buffers)
		return proc->buffer + proc->buffer_size - (void *)buffer->data;
	else
		return (size_t)list_entry(list_next(&buffer->entry), struct binder_buffer, entry) - (size_t)buffer->data;
}

/// CLEAR
static void binder_insert_free_buffer(struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	BUG_ON(!new_buffer->free);
	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: add free buffer, size %zd, at %p\n", proc->pid, binder_buffer_size(proc, new_buffer), new_buffer);

	rb_insert(proc->free_buffers, &new_buffer->rb_node);
}

/// CLEAR
static void binder_insert_allocated_buffer(struct binder_proc *proc, struct binder_buffer *new_buffer)
{
	BUG_ON(new_buffer->free);

	if (rb_search(proc->allocated_buffers, new_buffer->rb_node, keycompare_rbtree_binder_buffer_rb_node))
	      BUG();
	
	rb_insert(proc->allocated_buffers, &new_buffer->rb_node);
}

/// CLEAR
static struct binder_buffer *binder_buffer_lookup(struct binder_proc *proc, void __user *user_ptr)
{
	struct binder_buffer* kern_ptr = user_ptr - proc->user_buffer_offset - offsetof(struct binder_buffer, data);
	return rb_search(proc->allocated_buffers, kern_ptr, keycompare_rbtree_user_ptr);
}

/// CLEAR
static int binder_update_page_range(struct binder_proc *proc, int allocate, void *start, void *end, struct vma_struct *vma)
{
	void *page_addr;
	unsigned long user_page_addr;
	struct vma_struct tmp_area;
	struct Page **page;
	struct mm_struct *mm;

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: %s pages %p-%p\n", proc->pid, allocate ? "allocate" : "free", start, end);

	if (end <= start)
		return 0;

	if (vma)
		mm = NULL;
	else
		mm = proc->tsk->mm;

    // check mm = vma_mm
	if (mm) {
		lock_mm(mm);
		vma = proc->vma;
		if (vma && mm != proc->vma_vm_mm) {
			cprintf(KERN_ERR "binder: %d: vma mm and task mm mismatch\n", proc->pid);
			vma = NULL;
		}
	}

	if (allocate == 0)
		goto free_range;

	if (vma == NULL) {
		cprintf(KERN_ERR "binder: %d: binder_alloc_buf failed to map pages in userspace, no vma\n", proc->pid);
		goto err_no_vma;
	}

    // enumerate all pages
	for (page_addr = start; page_addr < end; page_addr += PGSIZE) {
		int ret;
		struct Page **page_array_ptr;
		page = &proc->pages[(page_addr - proc->buffer) / PGSIZE]; // get respective Page struct

		BUG_ON(*page);
		// TODO: preallocated
		// *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		*page = &proc->page_area[(page_addr - proc->buffer) / PGSIZE];	

		if (*page == NULL) {
			cprintf(KERN_ERR "binder: %d: binder_alloc_buf failed for page at %p\n", proc->pid, page_addr);
			goto err_alloc_page_failed;
		}

		tmp_area.addr = page_addr;
		tmp_area.size = PGSIZE + PGSIZE /* guard page? */;
		page_array_ptr = page;
		// map to kernel
		// ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
		if (ret) {
			cprintf(KERN_ERR "binder: %d: binder_alloc_buf failed to map page at %p in kernel\n", proc->pid, page_addr);
			goto err_map_kernel_failed;
		}
		user_page_addr = (uintptr_t)page_addr + proc->user_buffer_offset;

		// map to user space
		if (mm)  // read-only?
			ret = page_insert(mm->pgdir, page, user_page_addr, VM_READ);
		// ret = vm_insert_page(vma, user_page_addr, page[0]);
		if (ret) {
			kprintf(KERN_ERR "binder: %d: binder_alloc_buf failed to map page at %lx in userspace\n", proc->pid, user_page_addr);
			goto err_vm_insert_page_failed;
		}
		/* vm_insert_page does not seem to increment the refcount */
	}
    unlock_mm(mm);
	return 0;

free_range:
	for (page_addr = end - PGSIZE; page_addr >= start; page_addr -= PGSIZE) {
		page = &proc->pages[(page_addr - proc->buffer) / PGSIZE];
		if (vma)
		{
			// TODO:TODO:TODO:
			//*page = proc->page_area[(page_addr - proc->buffer) / PGSIZE];
			uintptr_t start_addr = (uintptr_t)page_addr + proc->user_buffer_offset;
			unmap_range(vma, start_addr, start_addr + PGSIZE);
			// FIXME: maybe bug here
		}
err_vm_insert_page_failed:
		// TODO:
		// unmap_kernel_range((unsigned long)page_addr, PGSIZE);
err_map_kernel_failed:
		// TODO:
		// __free_page(*page);
		*page = NULL;
err_alloc_page_failed:
		;
	}
err_no_vma:
    unlock_mm(mm);
	return -E_NOMEM;
}

/// MOD
static struct binder_buffer *binder_alloc_buf(struct binder_proc *proc, size_t data_size, size_t offsets_size, int is_async)
{
	struct rb_node *n = proc->free_buffers.rb_node;
	struct binder_buffer *buffer;
	size_t buffer_size;
	struct rb_node *best_fit = NULL;
	void *has_page_addr;
	void *end_page_addr;
	size_t size;

	if (proc->vma == NULL) {
		cprintf(KERN_ERR "binder: %d: binder_alloc_buf, no vma\n",
		       proc->pid);
		return NULL;
	}

	size = ROUNDUP(data_size, sizeof(void *)) + ROUNDUP(offsets_size, sizeof(void *));

	if (size < data_size || size < offsets_size) {
		binder_user_error("binder: %d: got transaction with invalid size %zd-%zd\n", proc->pid, data_size, offsets_size);
		return NULL;
	}

	if (is_async &&
	    proc->free_async_space < size + sizeof(struct binder_buffer)) {
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: binder_alloc_buf size %zd failed, no async space left\n", proc->pid, size);
		return NULL;
	}

	// TODO: best fit search
	while (n) {
		buffer = rb_entry(n, struct binder_buffer, rb_node);
		BUG_ON(!buffer->free);
		buffer_size = binder_buffer_size(proc, buffer);

		if (size < buffer_size) {
			best_fit = n;
			n = n->rb_left;
		} else if (size > buffer_size)
			n = n->rb_right;
		else {
			best_fit = n;
			break;
		}
	}
	if (best_fit == NULL) {
		cprintf(KERN_ERR "binder: %d: binder_alloc_buf size %zd failed, no address space\n", proc->pid, size);
		return NULL;
	}
	if (n == NULL) {
		buffer = rb_entry(best_fit, struct binder_buffer, rb_node);
		buffer_size = binder_buffer_size(proc, buffer);
	}

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: binder_alloc_buf size %zd got buffer %p size %zd\n", proc->pid, size, buffer, buffer_size);

	has_page_addr = (void *)(((uintptr_t)buffer->data + buffer_size) & PGMASK);
	if (n == NULL) {
		if (size + sizeof(struct binder_buffer) + 4 >= buffer_size)
			buffer_size = size; /* no room for other buffers */
		else
			buffer_size = size + sizeof(struct binder_buffer);
	}
	end_page_addr = (void *)PAGE_ALIGN((uintptr_t)buffer->data + buffer_size);
	if (end_page_addr > has_page_addr)
		end_page_addr = has_page_addr;
	if (binder_update_page_range(proc, 1, (void *)PAGE_ALIGN((uintptr_t)buffer->data), end_page_addr, NULL))
		return NULL;

	rb_erase(best_fit, &proc->free_buffers);
	buffer->free = 0;
	binder_insert_allocated_buffer(proc, buffer);
	if (buffer_size != size) {
		struct binder_buffer *new_buffer = (void *)buffer->data + size;
		list_add(&buffer->entry, &new_buffer->entry);
		new_buffer->free = 1;
		binder_insert_free_buffer(proc, new_buffer);
	}
	binder_debug(BINDER_DEBUG_BUFFER_ALLOC,
		     "binder: %d: binder_alloc_buf size %zd got %p\n", proc->pid, size, buffer);
	buffer->data_size = data_size;
	buffer->offsets_size = offsets_size;
	buffer->async_transaction = is_async;
	if (is_async) {
		proc->free_async_space -= size + sizeof(struct binder_buffer);
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC_ASYNC, "binder: %d: binder_alloc_buf size %zd async free %zd\n", proc->pid, size, proc->free_async_space);
	}

	return buffer;
}

/// UN
static void *buffer_start_page(struct binder_buffer *buffer)
{
	return (void *)((uintptr_t)buffer & PGMASK);
}

static void *buffer_end_page(struct binder_buffer *buffer)
{
	return (void *)(((uintptr_t)(buffer + 1) - 1) & PGMASK);
}

/// CLEAR
static void binder_delete_free_buffer(struct binder_proc *proc, struct binder_buffer *buffer)
{
	struct binder_buffer *prev, *next = NULL;
	int free_page_end = 1;
	int free_page_start = 1;

	BUG_ON(proc->buffers.next == &buffer->entry);
	prev = list_entry(list_prev(&buffer->entry), struct binder_buffer, entry);
	BUG_ON(!prev->free);
	if (buffer_end_page(prev) == buffer_start_page(buffer)) {
		free_page_start = 0;
		if (buffer_end_page(prev) == buffer_end_page(buffer))
			free_page_end = 0;
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC,
			     "binder: %d: merge free, buffer %p share page with %p\n", proc->pid, buffer, prev);
	}

	if (list_next(&buffer->entry) != &proc->buffers) { // list_is_not_last
		next = list_entry(list_next(&buffer->entry), struct binder_buffer, entry);
		if (buffer_start_page(next) == buffer_end_page(buffer)) {
			free_page_end = 0;
			if (buffer_start_page(next) == buffer_start_page(buffer))
				free_page_start = 0;
			binder_debug(BINDER_DEBUG_BUFFER_ALLOC,
				     "binder: %d: merge free, buffer  %p share page with %p\n", proc->pid, buffer, prev);
		}
	}
	list_del(&buffer->entry);
	if (free_page_start || free_page_end) {
		binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: merge free, buffer %p do "
			     "not share page%s%s with with %p or %p\n", proc->pid, buffer, free_page_start ? "" : " end",
			     free_page_end ? "" : " start", prev, next);
		binder_update_page_range(proc, 0, free_page_start ? buffer_start_page(buffer) : buffer_end_page(buffer),
			(free_page_end ? buffer_end_page(buffer) : buffer_start_page(buffer)) + PGSIZE, NULL);
	}
}

/// CLEAR
static void binder_free_buf(struct binder_proc *proc, struct binder_buffer *buffer)
{
	size_t size, buffer_size;

	buffer_size = binder_buffer_size(proc, buffer);

	size = ROUNDUP(buffer->data_size, sizeof(void *)) + ROUNDUP(buffer->offsets_size, sizeof(void *));

	binder_debug(BINDER_DEBUG_BUFFER_ALLOC, "binder: %d: binder_free_buf %p size %zd buffer"
		     "_size %zd\n", proc->pid, buffer, size, buffer_size);

	BUG_ON(buffer->free);
	BUG_ON(size > buffer_size);
	BUG_ON(buffer->transaction != NULL);
	BUG_ON((void *)buffer < proc->buffer);
	BUG_ON((void *)buffer > proc->buffer + proc->buffer_size);

	if (buffer->async_transaction) {
		proc->free_async_space += size + sizeof(struct binder_buffer);

		binder_debug(BINDER_DEBUG_BUFFER_ALLOC_ASYNC, "binder: %d: binder_free_buf size %zd async free %zd\n", proc->pid, size, proc->free_async_space);
	}

	binder_update_page_range(proc, 0, (void *)ROUNDUP((uintptr_t)buffer->data, PGSIZE), (void *)(((uintptr_t)buffer->data + buffer_size) & PGMASK), NULL);
	rb_erase(proc->allocated_buffers, &buffer->rb_node);
	buffer->free = 1;
	if (list_next(&buffer->entry) != &proc->buffers) { // !list_is_last(&buffer->entry, &proc->buffers))
		struct binder_buffer *next = list_entry(list_next(&buffer->entry), struct binder_buffer, entry);
		if (next->free) {
			rb_erase(proc->free_buffers, &next->rb_node);
			binder_delete_free_buffer(proc, next);
		}
	}
	if (list_next(&proc->buffers) != &buffer->entry) {
		struct binder_buffer *prev = list_entry(list_prev(&buffer->entry), struct binder_buffer, entry);
		if (prev->free) {
			binder_delete_free_buffer(proc, buffer);
			rb_erase(proc->free_buffers, &prev->rb_node);
			buffer = prev;
		}
	}
	binder_insert_free_buffer(proc, buffer);
}

/// CLEAR
static struct binder_node *binder_get_node(struct binder_proc *proc, void __user *ptr)
{
    rb_node* rbnode = rb_search(proc->nodes, keycompare_rbtree_binder_node_ptr, ptr);
    if (rbnode == NULL)
        return NULL;
    else
        return rb_entry(rbnode, struct binder_node, rb_node);
}

/// CLEAR
static struct binder_node *binder_new_node(struct binder_proc *proc, void __user *ptr, void __user *cookie)
{
	struct binder_node *node = kzalloc(sizeof(*node));
	if (node == NULL)
		return NULL;

	// add node to rb_tree
	rb_insert(proc->nodes, &node->rb_node);

	node->debug_id = ++binder_last_id;
	node->proc = proc;
	node->ptr = ptr;
	node->cookie = cookie;
	node->work.type = BINDER_WORK_NODE;

	list_init(&node->work.entry);
	list_init(&node->async_todo);
	binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d:%d node %d u%p c%p created\n",
		     proc->pid, current->pid, node->debug_id, node->ptr, node->cookie);
	return node;
}

/// CLEAR
static int binder_inc_node(struct binder_node *node, int strong, int internal, list_entry_t *target_list)
{
	if (strong) {
		if (internal) {
			if (target_list == NULL && node->internal_strong_refs == 0 &&
			    !(node == binder_context_mgr_node && node->has_strong_ref)) {
				cprintf(KERN_ERR "binder: invalid inc strong node for %d\n", node->debug_id);
				return -E_INVAL;
			}
			node->internal_strong_refs++;
		} else
			node->local_strong_refs++;
		if (!node->has_strong_ref && target_list) {
			list_del_init(&node->work.entry);
			list_add_before(target_list, &node->work.entry);
		}
	} else {
		if (!internal)
			node->local_weak_refs++;
		if (!node->has_weak_ref && list_empty(&node->work.entry)) {
			if (target_list == NULL) {
				cprintf(KERN_ERR "binder: invalid inc weak node for %d\n", node->debug_id);
				return -E_INVAL;
			}
			list_add_before(target_list, &node->work.entry);
		}
	}
	return 0;
}

/// CLEAR
static int binder_dec_node(struct binder_node *node, int strong, int internal)
{
	if (strong) {
		if (internal)
			node->internal_strong_refs--;
		else
			node->local_strong_refs--;
		if (node->local_strong_refs || node->internal_strong_refs)
			return 0;
	} else {
		if (!internal)
			node->local_weak_refs--;
		if (node->local_weak_refs || !list_empty(&node->refs))
			return 0;
	}
	if (node->proc && (node->has_strong_ref || node->has_weak_ref)) {
		if (list_empty(&node->work.entry)) {
			list_add_before(&node->proc->todo, &node->work.entry);
			wake_up_interruptible(&node->proc->wait);
		}
	} else {
		if (list_empty(&node->refs) && !node->local_strong_refs && !node->local_weak_refs) {
			list_del_init(&node->work.entry);
			if (node->proc) {
				rb_delete(node->proc->nodes, &node->rb_node);
				binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: refless node %d deleted\n", node->debug_id);
			} else {
				list_del(&node->dead_node);
				binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: dead node %d deleted\n", node->debug_id);
			}
			kfree(node);
		}
	}

	return 0;
}

/// CLEAR
static struct binder_ref *binder_get_ref(struct binder_proc *proc, uint32_t desc)
{
    rb_node* rbnode = rb_search(proc->refs_by_desc, keycompare_rbtree_binder_ref_desc, desc);
    if (rbnode == NULL)
        return NULL;
    else
        return rb_entry(rbnode, struct binder_ref, rb_node_desc);
}

/// CLEAR
static struct binder_ref *binder_get_ref_for_node(struct binder_proc *proc, struct binder_node *node)
{
	struct binder_ref* new_ref = kzalloc(sizeof(*ref));
	if (new_ref == NULL)
		return NULL;
	new_ref->debug_id = ++binder_last_id;
	new_ref->proc = proc;
	new_ref->node = node;

	// add to rb_tree
	rb_insert(proc->refs_by_node, &new_ref->rb_node_node);

	new_ref->desc = (node == binder_context_mgr_node) ? 0 : 1;

//// TODO: arrange new id ???
	// TODO: rb_node_first/last, rb_entry
	for (struct rb_node* n = rb_first(&proc->refs_by_desc); n != NULL; n = rb_node_next(&proc->refs_by_desc, n))
	{
		struct rb_node* ref = rb_entry(n, struct binder_ref, rb_node_desc);
		if (ref->desc > new_ref->desc)
			break;
		new_ref->desc = ref->desc + 1;
	}

	// check exist & add to tree
	if (rb_search(proc->refs_by_desc, keycompare_rbtree_binder_ref_desc) != NULL)
		panic("Desc dupppp");
	rb_insert(proc->refs_by_desc, &new_ref->rb_node_desc);

	if (node) {
	    // add head
		list_add(&node->refs, &new_ref->node_entry);

		binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d new ref %d desc %d for "
			     "node %d\n", proc->pid, new_ref->debug_id, new_ref->desc, node->debug_id);
	} else {
		binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d new ref %d desc %d for "
			     "dead node\n", proc->pid, new_ref->debug_id, new_ref->desc);
	}
	return new_ref;
}

/// CLEAR
static void binder_delete_ref(struct binder_ref *ref)
{
	binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d delete ref %d desc %d for "
		     "node %d\n", ref->proc->pid, ref->debug_id, ref->desc, ref->node->debug_id);

    // remove from rb_tree
	rb_delete(ref->proc->refs_by_desc, &ref->rb_node_desc);
	rb_delete(ref->proc->refs_by_node, &ref->rb_node_node);

    // strong ref need to dec the node count
	if (ref->strong)
		binder_dec_node(ref->node, 1, 1);

    // remove from ref node list, then dec weak ref count
	list_del(&ref->node_entry);
	binder_dec_node(ref->node, 0, 1);

	if (ref->death) {
		binder_debug(BINDER_DEBUG_DEAD_BINDER, "binder: %d delete ref %d desc %d "
			     "has death notification\n", ref->proc->pid, ref->debug_id, ref->desc);
		list_del(&ref->death->work.entry);
		kfree(ref->death);
	}
	kfree(ref);
}

/// CLEAR
static int binder_inc_ref(struct binder_ref *ref, int strong, list_entry_t *target_list)
{
	int ret;
	if (strong) {
		if (ref->strong == 0) {
			ret = binder_inc_node(ref->node, 1, 1, target_list);
			if (ret)
				return ret;
		}
		ref->strong++;
	} else {
		if (ref->weak == 0) {
			ret = binder_inc_node(ref->node, 0, 1, target_list);
			if (ret)
				return ret;
		}
		ref->weak++;
	}
	return 0;
}

/// CLEAR
static int binder_dec_ref(struct binder_ref *ref, int strong)
{
	if (strong) {
		if (ref->strong == 0) {
			binder_user_error("binder: %d invalid dec strong, ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->debug_id, ref->desc, ref->strong, ref->weak);
			return -E_INVAL;
		}
		ref->strong--;
		if (ref->strong == 0) {
			int ret;
			ret = binder_dec_node(ref->node, strong, 1);
			if (ret)
				return ret;
		}
	} else {
		if (ref->weak == 0) {
			binder_user_error("binder: %d invalid dec weak, ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->debug_id, ref->desc, ref->strong, ref->weak);
			return -E_INVAL;
		}
		ref->weak--;
	}
	if (ref->strong == 0 && ref->weak == 0)
		binder_delete_ref(ref);
	return 0;
}

/// CLEAR
static void binder_pop_transaction(struct binder_thread *target_thread, struct binder_transaction *t)
{
	if (target_thread) {
		BUG_ON(target_thread->transaction_stack != t);
		BUG_ON(target_thread->transaction_stack->from != target_thread);
		target_thread->transaction_stack =
			target_thread->transaction_stack->from_parent;
		t->from = NULL;
	}
	t->need_reply = 0;
	if (t->buffer)
		t->buffer->transaction = NULL;
	kfree(t);
}

/// CLEAR
static void binder_send_failed_reply(struct binder_transaction *t, uint32_t error_code)
{
	struct binder_thread *target_thread;
	BUG_ON(t->flags & TF_ONE_WAY);
	while (1) {
		target_thread = t->from;
		if (target_thread) {
			if (target_thread->return_error != BR_OK &&
			   target_thread->return_error2 == BR_OK) {
				target_thread->return_error2 =
					target_thread->return_error;
				target_thread->return_error = BR_OK;
			}
			if (target_thread->return_error == BR_OK) {
				binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,
					     "binder: send failed reply for "
					     "transaction %d to %d:%d\n",
					      t->debug_id, target_thread->proc->pid,
					      target_thread->pid);

				binder_pop_transaction(target_thread, t);
				target_thread->return_error = error_code;
				wake_up_interruptible(&target_thread->wait);
			} else {
				cprintf(KERN_ERR "binder: reply failed, target "
					"thread, %d:%d, has error code %d "
					"already\n", target_thread->proc->pid,
					target_thread->pid,
					target_thread->return_error);
			}
			return;
		} else {
			struct binder_transaction *next = t->from_parent;

			binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,
				     "binder: send failed reply "
				     "for transaction %d, target dead\n",
				     t->debug_id);

			binder_pop_transaction(target_thread, t);
			if (next == NULL) {
				binder_debug(BINDER_DEBUG_DEAD_BINDER,
					     "binder: reply failed,"
					     " no target thread at root\n");
				return;
			}
			t = next;
			binder_debug(BINDER_DEBUG_DEAD_BINDER,
				     "binder: reply failed, no target "
				     "thread -- retry %d\n", t->debug_id);
		}
	}
}

/// CLEAR ???
static void binder_transaction_buffer_release(struct binder_proc *proc, struct binder_buffer *buffer, size_t *failed_at)
{
	size_t *offp, *off_end;
	int debug_id = buffer->debug_id;

	binder_debug(BINDER_DEBUG_TRANSACTION, "binder: %d buffer release %d, size %zd-%zd, failed at %p\n",
		     proc->pid, buffer->debug_id, buffer->data_size, buffer->offsets_size, failed_at);

	if (buffer->target_node)
		binder_dec_node(buffer->target_node, 1, 0);

	offp = (size_t *)(buffer->data + ROUNDUP(buffer->data_size, sizeof(void *)));
	if (failed_at)
		off_end = failed_at;
	else
		off_end = (void *)offp + buffer->offsets_size;
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp > buffer->data_size - sizeof(*fp) || buffer->data_size < sizeof(*fp) || !((*offp) % sizeof(void *) == 0)) {
			cprintf(KERN_ERR "binder: transaction release %d bad offset %zd, size %zd\n", debug_id, *offp, buffer->data_size);
			continue;
		}
		fp = (struct flat_binder_object *)(buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				cprintf(KERN_ERR "binder: transaction release %d bad node %p\n", debug_id, fp->binder);
				break;
			}
			binder_debug(BINDER_DEBUG_TRANSACTION, "        node %d u%p\n", node->debug_id, node->ptr);
			binder_dec_node(node, fp->type == BINDER_TYPE_BINDER, 0);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				cprintf(KERN_ERR "binder: transaction release %d bad handle %ld\n", debug_id, fp->handle);
				break;
			}
			binder_debug(BINDER_DEBUG_TRANSACTION, "        ref %d desc %d (node %d)\n", ref->debug_id, ref->desc, ref->node->debug_id);
			binder_dec_ref(ref, fp->type == BINDER_TYPE_HANDLE);
		} break;

		case BINDER_TYPE_FD:
			binder_debug(BINDER_DEBUG_TRANSACTION, "        fd %ld\n", fp->handle);
			if (failed_at)
				task_close_fd(proc, fp->handle);
			break;

		default:
			cprintf(KERN_ERR "binder: transaction release %d bad object type %lx\n", debug_id, fp->type);
			break;
		}
	}
}

/// C???
static void binder_transaction(struct binder_proc *proc, struct binder_thread *thread, struct binder_transaction_data *tr, int reply)
{
	struct binder_transaction *t;
	struct binder_work *tcomplete;
	size_t *offp, *off_end;
	struct binder_proc *target_proc;
	struct binder_thread *target_thread = NULL;
	struct binder_node *target_node = NULL;
	list_entry_t *target_list;
	wait_queue_head_t *target_wait;
	struct binder_transaction *in_reply_to = NULL;
	struct binder_transaction_log_entry *e;
	uint32_t return_error;

	e = binder_transaction_log_add(&binder_transaction_log);
	e->call_type = reply ? 2 : !!(tr->flags & TF_ONE_WAY);
	e->from_proc = proc->pid;
	e->from_thread = thread->pid;
	e->target_handle = tr->target.handle;
	e->data_size = tr->data_size;
	e->offsets_size = tr->offsets_size;

	if (reply) {
		in_reply_to = thread->transaction_stack;
		if (in_reply_to == NULL) {
			binder_user_error("binder: %d:%d got reply transaction "
					  "with no transaction stack\n",
					  proc->pid, thread->pid);
			return_error = BR_FAILED_REPLY;
			goto err_empty_call_stack;
		}
		binder_set_nice(in_reply_to->saved_priority);
		if (in_reply_to->to_thread != thread) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad transaction stack,"
				" transaction %d has target %d:%d\n",
				proc->pid, thread->pid, in_reply_to->debug_id,
				in_reply_to->to_proc ?
				in_reply_to->to_proc->pid : 0,
				in_reply_to->to_thread ?
				in_reply_to->to_thread->pid : 0);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			goto err_bad_call_stack;
		}
		thread->transaction_stack = in_reply_to->to_parent;
		target_thread = in_reply_to->from;
		if (target_thread == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		if (target_thread->transaction_stack != in_reply_to) {
			binder_user_error("binder: %d:%d got reply transaction "
				"with bad target transaction stack %d, "
				"expected %d\n",
				proc->pid, thread->pid,
				target_thread->transaction_stack ?
				target_thread->transaction_stack->debug_id : 0,
				in_reply_to->debug_id);
			return_error = BR_FAILED_REPLY;
			in_reply_to = NULL;
			target_thread = NULL;
			goto err_dead_binder;
		}
		target_proc = target_thread->proc;
	} else {
		if (tr->target.handle) {
			struct binder_ref *ref;
			ref = binder_get_ref(proc, tr->target.handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got "
					"transaction to invalid handle\n",
					proc->pid, thread->pid);
				return_error = BR_FAILED_REPLY;
				goto err_invalid_target_handle;
			}
			target_node = ref->node;
		} else {
			target_node = binder_context_mgr_node;
			if (target_node == NULL) {
				return_error = BR_DEAD_REPLY;
				goto err_no_context_mgr_node;
			}
		}
		e->to_node = target_node->debug_id;
		target_proc = target_node->proc;
		if (target_proc == NULL) {
			return_error = BR_DEAD_REPLY;
			goto err_dead_binder;
		}
		if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) {
			struct binder_transaction *tmp;
			tmp = thread->transaction_stack;
			if (tmp->to_thread != thread) {
				binder_user_error("binder: %d:%d got new "
					"transaction with bad transaction stack"
					", transaction %d has target %d:%d\n",
					proc->pid, thread->pid, tmp->debug_id,
					tmp->to_proc ? tmp->to_proc->pid : 0,
					tmp->to_thread ?
					tmp->to_thread->pid : 0);
				return_error = BR_FAILED_REPLY;
				goto err_bad_call_stack;
			}
			while (tmp) {
				if (tmp->from && tmp->from->proc == target_proc)
					target_thread = tmp->from;
				tmp = tmp->from_parent;
			}
		}
	}
	if (target_thread) {
		e->to_thread = target_thread->pid;
		target_list = &target_thread->todo;
		target_wait = &target_thread->wait;
	} else {
		target_list = &target_proc->todo;
		target_wait = &target_proc->wait;
	}
	e->to_proc = target_proc->pid;

	/* TODO: reuse incoming transaction for reply */
	t = kzalloc(sizeof(*t));
	if (t == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_alloc_t_failed;
	}

	tcomplete = kzalloc(sizeof(*tcomplete));
	if (tcomplete == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_alloc_tcomplete_failed;
	}

	t->debug_id = ++binder_last_id;
	e->debug_id = t->debug_id;

	if (reply)
		binder_debug(BINDER_DEBUG_TRANSACTION,
			     "binder: %d:%d BC_REPLY %d -> %d:%d, data %p-%p size %zd-%zd\n",
			     proc->pid, thread->pid, t->debug_id, target_proc->pid, target_thread->pid,
			     tr->data.ptr.buffer, tr->data.ptr.offsets, tr->data_size, tr->offsets_size);
	else
		binder_debug(BINDER_DEBUG_TRANSACTION,
			     "binder: %d:%d BC_TRANSACTION %d -> %d - node %d, data %p-%p size %zd-%zd\n",
			     proc->pid, thread->pid, t->debug_id, target_proc->pid, target_node->debug_id,
			     tr->data.ptr.buffer, tr->data.ptr.offsets, tr->data_size, tr->offsets_size);

	if (!reply && !(tr->flags & TF_ONE_WAY))
		t->from = thread;
	else
		t->from = NULL;
// TODO: no euid
//	t->sender_euid = proc->tsk->cred->euid;
	t->to_proc = target_proc;
	t->to_thread = target_thread;
	t->code = tr->code;
	t->flags = tr->flags;
	t->priority = task_nice(current);

//	trace_binder_transaction(reply, t, target_node);

	t->buffer = binder_alloc_buf(target_proc, tr->data_size, tr->offsets_size, !reply && (t->flags & TF_ONE_WAY));
	if (t->buffer == NULL) {
		return_error = BR_FAILED_REPLY;
		goto err_binder_alloc_buf_failed;
	}
	t->buffer->allow_user_free = 0;
	t->buffer->debug_id = t->debug_id;
	t->buffer->transaction = t;
	t->buffer->target_node = target_node;
//	trace_binder_transaction_alloc_buf(t->buffer);
	if (target_node)
		binder_inc_node(target_node, 1, 0, NULL);

	offp = (size_t *)(t->buffer->data + ROUNDUP(tr->data_size, sizeof(void *)));

	if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) {
		binder_user_error("binder: %d:%d got transaction with invalid data ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}
	if (copy_from_user(offp, tr->data.ptr.offsets, tr->offsets_size)) {
		binder_user_error("binder: %d:%d got transaction with invalid offsets ptr\n", proc->pid, thread->pid);
		return_error = BR_FAILED_REPLY;
		goto err_copy_data_failed;
	}
	if (!IS_ALIGNED(tr->offsets_size, sizeof(size_t))) {
		binder_user_error("binder: %d:%d got transaction with invalid offsets size, %zd\n",
			proc->pid, thread->pid, tr->offsets_size);
		return_error = BR_FAILED_REPLY;
		goto err_bad_offset;
	}
	off_end = (void *)offp + tr->offsets_size;
	for (; offp < off_end; offp++) {
		struct flat_binder_object *fp;
		if (*offp > t->buffer->data_size - sizeof(*fp) ||
		    t->buffer->data_size < sizeof(*fp) ||
		    !IS_ALIGNED(*offp, sizeof(void *))) {
			binder_user_error("binder: %d:%d got transaction with invalid offset, %zd\n", proc->pid, thread->pid, *offp);
			return_error = BR_FAILED_REPLY;
			goto err_bad_offset;
		}
		fp = (struct flat_binder_object *)(t->buffer->data + *offp);
		switch (fp->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct binder_ref *ref;
			struct binder_node *node = binder_get_node(proc, fp->binder);
			if (node == NULL) {
				node = binder_new_node(proc, fp->binder, fp->cookie);
				if (node == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_new_node_failed;
				}
				node->min_priority = fp->flags & FLAT_BINDER_FLAG_PRIORITY_MASK;
				node->accept_fds = !!(fp->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS);
			}
			if (fp->cookie != node->cookie) {
				binder_user_error("binder: %d:%d sending u%p node %d, cookie mismatch %p != %p\n",
					proc->pid, thread->pid, fp->binder, node->debug_id, fp->cookie, node->cookie);
				goto err_binder_get_ref_for_node_failed;
			}
			ref = binder_get_ref_for_node(target_proc, node);
			if (ref == NULL) {
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_for_node_failed;
			}
			if (fp->type == BINDER_TYPE_BINDER)
				fp->type = BINDER_TYPE_HANDLE;
			else
				fp->type = BINDER_TYPE_WEAK_HANDLE;
			fp->handle = ref->desc;
			binder_inc_ref(ref, fp->type == BINDER_TYPE_HANDLE, &thread->todo);

//			trace_binder_transaction_node_to_ref(t, node, ref);
			binder_debug(BINDER_DEBUG_TRANSACTION, "        node %d u%p -> ref %d desc %d\n",
				     node->debug_id, node->ptr, ref->debug_id, ref->desc);
		} break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct binder_ref *ref = binder_get_ref(proc, fp->handle);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d got transaction with invalid handle, %ld\n", proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_binder_get_ref_failed;
			}
			if (ref->node->proc == target_proc) {
				if (fp->type == BINDER_TYPE_HANDLE)
					fp->type = BINDER_TYPE_BINDER;
				else
					fp->type = BINDER_TYPE_WEAK_BINDER;
				fp->binder = ref->node->ptr;
				fp->cookie = ref->node->cookie;
				binder_inc_node(ref->node, fp->type == BINDER_TYPE_BINDER, 0, NULL);
//				trace_binder_transaction_ref_to_node(t, ref);
				binder_debug(BINDER_DEBUG_TRANSACTION,
					     "        ref %d desc %d -> node %d u%p\n",
					     ref->debug_id, ref->desc, ref->node->debug_id, ref->node->ptr);
			} else {
				struct binder_ref *new_ref;
				new_ref = binder_get_ref_for_node(target_proc, ref->node);
				if (new_ref == NULL) {
					return_error = BR_FAILED_REPLY;
					goto err_binder_get_ref_for_node_failed;
				}
				fp->handle = new_ref->desc;
				binder_inc_ref(new_ref, fp->type == BINDER_TYPE_HANDLE, NULL);
//				trace_binder_transaction_ref_to_ref(t, ref,
//								    new_ref);
				binder_debug(BINDER_DEBUG_TRANSACTION,
					     "        ref %d desc %d -> ref %d desc %d (node %d)\n",
					     ref->debug_id, ref->desc, new_ref->debug_id, new_ref->desc, ref->node->debug_id);
			}
		} break;

		case BINDER_TYPE_FD: {
			int target_fd;
			struct file *file;

			if (reply) {
				if (!(in_reply_to->flags & TF_ACCEPT_FDS)) {
					binder_user_error("binder: %d:%d got reply with fd, %ld, but target does not allow fds\n",
						proc->pid, thread->pid, fp->handle);
					return_error = BR_FAILED_REPLY;
					goto err_fd_not_allowed;
				}
			} else if (!target_node->accept_fds) {
				binder_user_error("binder: %d:%d got transaction with fd, %ld, but target does not allow fds\n",
					proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fd_not_allowed;
			}

			file = fget(fp->handle);
			if (file == NULL) {
				binder_user_error("binder: %d:%d got transaction with invalid fd, %ld\n", proc->pid, thread->pid, fp->handle);
				return_error = BR_FAILED_REPLY;
				goto err_fget_failed;
			}
			target_fd = task_get_unused_fd_flags(target_proc);// CLO_EXEC
			if (target_fd < 0) {
				fput(file);
				return_error = BR_FAILED_REPLY;
				goto err_get_unused_fd_failed;
			}
			task_fd_install(target_proc, target_fd, file);
//			trace_binder_transaction_fd(t, fp->handle, target_fd);
			binder_debug(BINDER_DEBUG_TRANSACTION, "        fd %ld -> %d\n", fp->handle, target_fd);
			/* TODO: fput? */
			fp->handle = target_fd;
		} break;

		default:
			binder_user_error("binder: %d:%d got transaction with invalid object type, %lx\n", proc->pid, thread->pid, fp->type);
			return_error = BR_FAILED_REPLY;
			goto err_bad_object_type;
		}
	}
	if (reply) {
		BUG_ON(t->buffer->async_transaction != 0);
		binder_pop_transaction(target_thread, in_reply_to);
	} else if (!(t->flags & TF_ONE_WAY)) {
		BUG_ON(t->buffer->async_transaction != 0);
		t->need_reply = 1;
		t->from_parent = thread->transaction_stack;
		thread->transaction_stack = t;
	} else {
		BUG_ON(target_node == NULL);
		BUG_ON(t->buffer->async_transaction != 1);
		if (target_node->has_async_transaction) {
			target_list = &target_node->async_todo;
			target_wait = NULL;
		} else
			target_node->has_async_transaction = 1;
	}
	t->work.type = BINDER_WORK_TRANSACTION;
	list_add_tail(&t->work.entry, target_list);
	tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
	list_add_tail(&tcomplete->entry, &thread->todo);
	if (target_wait)
		wake_up_interruptible(target_wait);
	return;

err_get_unused_fd_failed:
err_fget_failed:
err_fd_not_allowed:
err_binder_get_ref_for_node_failed:
err_binder_get_ref_failed:
err_binder_new_node_failed:
err_bad_object_type:
err_bad_offset:
err_copy_data_failed:
//	trace_binder_transaction_failed_buffer_release(t->buffer);
	binder_transaction_buffer_release(target_proc, t->buffer, offp);
	t->buffer->transaction = NULL;
	binder_free_buf(target_proc, t->buffer);
err_binder_alloc_buf_failed:
	kfree(tcomplete);
err_alloc_tcomplete_failed:
	kfree(t);
err_alloc_t_failed:
err_bad_call_stack:
err_empty_call_stack:
err_dead_binder:
err_invalid_target_handle:
err_no_context_mgr_node:
	binder_debug(BINDER_DEBUG_FAILED_TRANSACTION,
		     "binder: %d:%d transaction failed %d, size %zd-%zd\n", proc->pid, thread->pid, return_error, tr->data_size, tr->offsets_size);

	{
		struct binder_transaction_log_entry *fe;
		fe = binder_transaction_log_add(&binder_transaction_log_failed);
		*fe = *e;
	}

	BUG_ON(thread->return_error != BR_OK);
	if (in_reply_to) {
		thread->return_error = BR_TRANSACTION_COMPLETE;
		binder_send_failed_reply(in_reply_to, return_error);
	} else
		thread->return_error = return_error;
}

/// C???
int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread, void __user *buffer, int size, signed long *consumed)
{
	uint32_t cmd;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	while (ptr < end && thread->return_error == BR_OK)
	{
		if (copy_from_user(current->mm, &cmd, (uint32_t __user *)ptr, sizeof(uint32_t), 0))
			return -E_FAULT;
		ptr += sizeof(uint32_t);
		switch (cmd) {
        // inc or dec the reference count of Binder, arg = Binder Ref ID
		case BC_INCREFS:
		case BC_ACQUIRE:
		case BC_RELEASE:
		case BC_DECREFS:
		{
			uint32_t target;
			struct binder_ref *ref;
			const char *debug_string;

			if (copy_from_user(current->mm, &target, (uint32_t __user *)ptr, sizeof(uint32_t), 0))
				return -E_FAULT;
			ptr += sizeof(uint32_t);
			if (target == 0 && binder_context_mgr_node && (cmd == BC_INCREFS || cmd == BC_ACQUIRE))
			{
                // from service manager node
				ref = binder_get_ref_for_node(proc, binder_context_mgr_node);
				if (ref->desc != target)
				{
					binder_user_error("binder: %d:%d tried to acquire reference to desc 0, got %d instead\n",
						proc->pid, thread->pid, ref->desc);
				}
			} else
				ref = binder_get_ref(proc, target);

			if (ref == NULL) {
				binder_user_error("binder: %d:%d refcount change on invalid ref %d\n", proc->pid, thread->pid, target);
				break;
			}

			// execute cmd
			switch (cmd) {
			case BC_INCREFS:
				debug_string = "IncRefs";
				binder_inc_ref(ref, 0, NULL);
				break;
			case BC_ACQUIRE:
				debug_string = "Acquire";
				binder_inc_ref(ref, 1, NULL);
				break;
			case BC_RELEASE:
				debug_string = "Release";
				binder_dec_ref(ref, 1);
				break;
			case BC_DECREFS:
			default:
				debug_string = "DecRefs";
				binder_dec_ref(ref, 0);
				break;
			}
			binder_debug(BINDER_DEBUG_USER_REFS, "binder: %d:%d %s ref %d desc %d s %d w %d for node %d\n",
				     proc->pid, thread->pid, debug_string, ref->debug_id, ref->desc, ref->strong, ref->weak, ref->node->debug_id);
			break;
		}
		case BC_INCREFS_DONE:
		case BC_ACQUIRE_DONE: {
			void __user *node_ptr;
			void *cookie;
			struct binder_node *node;

			if (copy_from_user(current->mm, node_ptr, (void * __user *)ptr, sizeof(void*), 0))
				return -E_FAULT;
			ptr += sizeof(void *);
			if (copy_from_user(current->mm, cookie, (void * __user *)ptr), sizeof(void*), 0))
				return -E_FAULT;
			ptr += sizeof(void *);
			node = binder_get_node(proc, node_ptr);
			// check node match
			if (node == NULL) {
				binder_user_error("binder: %d:%d %s u%p no match\n", proc->pid, thread->pid,
                      cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE", node_ptr);
				break;
			}
			// check cookie match ? cookie address should not be altered during session??
			if (cookie != node->cookie) {
				binder_user_error("binder: %d:%d %s u%p node %d cookie mismatch %p != %p\n", proc->pid, thread->pid,
					cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE", node_ptr, node->debug_id, cookie, node->cookie);
				break;
			}
			if (cmd == BC_ACQUIRE_DONE) {
				if (node->pending_strong_ref == 0) {
					binder_user_error("binder: %d:%d BC_ACQUIRE_DONE node %d has "
						"no pending acquire request\n", proc->pid, thread->pid, node->debug_id);
					break;
				}
				node->pending_strong_ref = 0;
			} else {
				if (node->pending_weak_ref == 0) {
					binder_user_error("binder: %d:%d BC_INCREFS_DONE node %d has "
						"no pending increfs request\n", proc->pid, thread->pid, node->debug_id);
					break;
				}
				node->pending_weak_ref = 0;
			}
			binder_dec_node(node, cmd == BC_ACQUIRE_DONE, 0);
			binder_debug(BINDER_DEBUG_USER_REFS,
				     "binder: %d:%d %s node %d ls %d lw %d\n", proc->pid, thread->pid,
				     cmd == BC_INCREFS_DONE ? "BC_INCREFS_DONE" : "BC_ACQUIRE_DONE",
				     node->debug_id, node->local_strong_refs, node->local_weak_refs);
			break;
		}
		case BC_ATTEMPT_ACQUIRE:
			cprintf(KERN_ERR "binder: BC_ATTEMPT_ACQUIRE not supported\n");
			return -E_INVAL;
		case BC_ACQUIRE_RESULT:
			cprintf(KERN_ERR "binder: BC_ACQUIRE_RESULT not supported\n");
			return -E_INVAL;

		case BC_FREE_BUFFER: {
			void __user *data_ptr;
			struct binder_buffer *buffer;

			if (copy_from_user(current->mm, data_ptr, (void * __user *)ptr, sizeof(void*), 0))
				return -E_FAULT;
			ptr += sizeof(void *);

			buffer = binder_buffer_lookup(proc, data_ptr);
			if (buffer == NULL) {
				binder_user_error("binder: %d:%d BC_FREE_BUFFER u%p no match\n", proc->pid, thread->pid, data_ptr);
				break;
			}
			if (!buffer->allow_user_free) {
				binder_user_error("binder: %d:%d BC_FREE_BUFFER u%p matched "
					"unreturned buffer\n", proc->pid, thread->pid, data_ptr);
				break;
			}
			binder_debug(BINDER_DEBUG_FREE_BUFFER,
				     "binder: %d:%d BC_FREE_BUFFER u%p found buffer %d for %s transaction\n",
				     proc->pid, thread->pid, data_ptr, buffer->debug_id, buffer->transaction ? "active" : "finished");

			if (buffer->transaction) {
				buffer->transaction->buffer = NULL;
				buffer->transaction = NULL;
			}
			if (buffer->async_transaction && buffer->target_node) { /// ?????
				BUG_ON(!buffer->target_node->has_async_transaction);
				if (list_empty(&buffer->target_node->async_todo))
					buffer->target_node->has_async_transaction = 0;
				else
				{
					// list_move_tail
					list_entry_t* tail = list_next(&buffer->target_node->async_todo);
					list_del_init(tail);
					list_add_before(&thread->todo, tail);
				}
			}
//			trace_binder_transaction_buffer_release(buffer);
            // do release mem
			binder_transaction_buffer_release(proc, buffer, NULL);
			binder_free_buf(proc, buffer);
			break;
		}

		case BC_TRANSACTION:
		case BC_REPLY: {
			struct binder_transaction_data tr;

			if (copy_from_user(current->mm, &tr, ptr, sizeof(tr), 0))
				return -E_FAULT;
			ptr += sizeof(tr);
			binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
			break;
		}

		case BC_REGISTER_LOOPER:
			binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d BC_REGISTER_LOOPER\n", proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_ENTERED) {
			    thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR: BC_REGISTER_LOOPER called after BC_ENTER_LOOPER\n", proc->pid, thread->pid);
			} else if (proc->requested_threads == 0) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR: BC_REGISTER_LOOPER called without request\n", proc->pid, thread->pid);
			} else {
				proc->requested_threads--;
				proc->requested_threads_started++;
			}
			thread->looper |= BINDER_LOOPER_STATE_REGISTERED;
			break;
		case BC_ENTER_LOOPER:
			binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d BC_ENTER_LOOPER\n", proc->pid, thread->pid);
			if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) {
				thread->looper |= BINDER_LOOPER_STATE_INVALID;
				binder_user_error("binder: %d:%d ERROR: BC_ENTER_LOOPER called after BC_REGISTER_LOOPER\n", proc->pid, thread->pid);
			}
			thread->looper |= BINDER_LOOPER_STATE_ENTERED;
			break;
		case BC_EXIT_LOOPER:
			binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d BC_EXIT_LOOPER\n", proc->pid, thread->pid);
			thread->looper |= BINDER_LOOPER_STATE_EXITED;
			break;

		case BC_REQUEST_DEATH_NOTIFICATION:
		case BC_CLEAR_DEATH_NOTIFICATION:
		{
			uint32_t target;
			void __user *cookie;
			struct binder_ref *ref;
			struct binder_ref_death *death;

			if (copy_from_user(current->mm, &target, (uint32_t __user *)ptr, sizeof(uint32_t), 0))
				return -E_FAULT;
			ptr += sizeof(uint32_t);
			if (copy_from_user(current->mm, &cookie, (void __user * __user *)ptr, sizeof(uint32_t), 0))
				return -E_FAULT;
			ptr += sizeof(void *);
			ref = binder_get_ref(proc, target);
			if (ref == NULL) {
				binder_user_error("binder: %d:%d %s invalid ref %d\n",
					proc->pid, thread->pid, cmd == BC_REQUEST_DEATH_NOTIFICATION ? "BC_REQUEST_DEATH_NOTIFICATION" :
					"BC_CLEAR_DEATH_NOTIFICATION", target);
				break;
			}

			binder_debug(BINDER_DEBUG_DEATH_NOTIFICATION,
				     "binder: %d:%d %s %p ref %d desc %d s %d w %d for node %d\n", proc->pid, thread->pid,
				     cmd == BC_REQUEST_DEATH_NOTIFICATION ? "BC_REQUEST_DEATH_NOTIFICATION" : "BC_CLEAR_DEATH_NOTIFICATION", cookie, ref->debug_id, ref->desc,
				     ref->strong, ref->weak, ref->node->debug_id);

			if (cmd == BC_REQUEST_DEATH_NOTIFICATION) {
				if (ref->death) {
					binder_user_error("binder: %d:%d BC_REQUEST_DEATH_NOTIFICATION death notification already set\n", proc->pid, thread->pid);
					break;
				}
				death = kzalloc(sizeof(*death));
				if (death == NULL) {
					thread->return_error = BR_ERROR;
					binder_debug(BINDER_DEBUG_FAILED_TRANSACTION, "binder: %d:%d BC_REQUEST_DEATH_NOTIFICATION failed\n", proc->pid, thread->pid);
					break;
				}
				list_init(&death->work.entry);
				death->cookie = cookie;
				ref->death = death;
				if (ref->node->proc == NULL)
				{
					ref->death->work.type = BINDER_WORK_DEAD_BINDER;
					if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED))
					{
						list_add_before(&thread->todo, &ref->death->work.entry); // list_add_tail
					} else {
						list_add_before(&proc->todo, &ref->death->work.entry);
						wake_up_interruptible(&proc->wait);
					}
				}
			} else {
				if (ref->death == NULL) {
					binder_user_error("binder: %d:%d BC_CLEAR_DEATH_NOTIFICATION death notification not active\n", proc->pid, thread->pid);
					break;
				}
				death = ref->death;
				if (death->cookie != cookie) {
					binder_user_error("binder: %d:%d BC_CLEAR_DEATH_NOTIFICATION death notification cookie mismatch %p != %p\n",
						proc->pid, thread->pid, death->cookie, cookie);
					break;
				}
				ref->death = NULL;
				if (list_empty(&death->work.entry)) {
					death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
					if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
						list_add_before(&thread->todo, &death->work.entry);
					} else {
						list_add_before(&proc->todo, &death->work.entry);
						wake_up_interruptible(&proc->wait);
					}
				} else {
					BUG_ON(death->work.type != BINDER_WORK_DEAD_BINDER);
					death->work.type = BINDER_WORK_DEAD_BINDER_AND_CLEAR;
				}
			}
		} break;
		case BC_DEAD_BINDER_DONE: {
			struct binder_work *w;
			void __user *cookie;
			struct binder_ref_death *death = NULL;
			if (copy_from_user(current->mm, &cookie, (void __user * __user *)ptr), sizeof(void*), 0))
				return -E_FAULT;

			ptr += sizeof(void *);
			// list_for_each_entry(w, &proc->delivered_death, entry)
			for (list_entry_t w = list_next(&proc->delivered_death); w != &proc->delivered_death; w = list_next(w))
			{
				struct binder_ref_death *tmp_death = container_of(w, struct binder_ref_death, work);
				if (tmp_death->cookie == cookie) {
					death = tmp_death;
					break;
				}
			}
			binder_debug(BINDER_DEBUG_DEAD_BINDER,
				     "binder: %d:%d BC_DEAD_BINDER_DONE %p found %p\n", proc->pid, thread->pid, cookie, death);
			if (death == NULL) {
				binder_user_error("binder: %d:%d BC_DEAD_BINDER_DONE %p not found\n", proc->pid, thread->pid, cookie);
				break;
			}

			list_del_init(&death->work.entry);
			if (death->work.type == BINDER_WORK_DEAD_BINDER_AND_CLEAR) {
				death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
				if (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) {
					list_add_before(&thread->todo, &death->work.entry);
				} else {
					list_add_before(&proc->todo, &death->work.entry);
					wake_up_interruptible(&proc->wait);
				}
			}
		} break;

		default:
			cprintf(KERN_ERR "binder: %d:%d unknown command %d\n", proc->pid, thread->pid, cmd);
			return -E_INVAL;
		}
		*consumed = ptr - buffer;
	}
	return 0;
}

/// CLEAR
static int binder_has_proc_work(struct binder_proc *proc, struct binder_thread *thread)
{
	return !list_empty(&proc->todo) ||
		(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

/// CLEAR
static int binder_has_thread_work(struct binder_thread *thread)
{
	return !list_empty(&thread->todo) || thread->return_error != BR_OK ||
		(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN);
}

/// ???
static int binder_thread_read(struct binder_proc *proc, struct binder_thread *thread,
			      void  __user *buffer, int size, signed long *consumed, int non_block)
{
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	int ret = 0;
	int wait_for_proc_work;

	if (*consumed == 0) {
		if (put_user(BR_NOOP, (uint32_t __user *)ptr))
			return -E_FAULT;
		ptr += sizeof(uint32_t);
	}

retry:
	wait_for_proc_work = thread->transaction_stack == NULL &&
				list_empty(&thread->todo);

	if (thread->return_error != BR_OK && ptr < end) {
		if (thread->return_error2 != BR_OK) {
			if (put_user(thread->return_error2, (uint32_t __user *)ptr))
				return -E_FAULT;
			ptr += sizeof(uint32_t);
			binder_stat_br(proc, thread, thread->return_error2);
			if (ptr == end)
				goto done;
			thread->return_error2 = BR_OK;
		}
		if (copy_to_user(current->mm, &thread->return_error, (uint32_t __user *)ptr, sizeof(uint32_t)))
			return -E_FAULT;
		ptr += sizeof(uint32_t);
		binder_stat_br(proc, thread, thread->return_error);
		thread->return_error = BR_OK;
		goto done;
	}

	thread->looper |= BINDER_LOOPER_STATE_WAITING;
	if (wait_for_proc_work)
		proc->ready_threads++;

	binder_unlock();

	if (wait_for_proc_work) {
		if (!(thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED))) {
			binder_user_error("binder: %d:%d ERROR: Thread waiting for process work before calling BC_REGISTER_"
				"LOOPER or BC_ENTER_LOOPER (state %x)\n", proc->pid, thread->pid, thread->looper);
			wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
		}
		binder_set_nice(proc->default_priority);
		if (non_block) {
			if (!binder_has_proc_work(proc, thread))
				ret = -E_AGAIN;
		} else
			ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
	} else {
		if (non_block) {
			if (!binder_has_thread_work(thread))
				ret = -E_AGAIN;
		} else
			ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
	}

	binder_lock();

	if (wait_for_proc_work)
		proc->ready_threads--;
	thread->looper &= ~BINDER_LOOPER_STATE_WAITING;

	if (ret)
		return ret;

	while (1) {
		uint32_t cmd;
		struct binder_transaction_data tr;
		struct binder_work *w;
		struct binder_transaction *t = NULL;

		if (!list_empty(&thread->todo))
			w = list_entry(list_next(&thread->todo), struct binder_work, entry);
		else if (!list_empty(&proc->todo) && wait_for_proc_work)
			w = list_entry(list_next(&proc->todo, struct binder_work, entry);
		else {
			if (ptr - buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
				goto retry;
			break;
		}

		if (end - ptr < sizeof(tr) + 4)
			break;

		switch (w->type) {
		case BINDER_WORK_TRANSACTION: {
			t = container_of(w, struct binder_transaction, work);
		} break;
		case BINDER_WORK_TRANSACTION_COMPLETE: {
			cmd = BR_TRANSACTION_COMPLETE;
			if (put_user(cmd, (uint32_t __user *)ptr))
				return -E_FAULT;
			ptr += sizeof(uint32_t);

			binder_stat_br(proc, thread, cmd);
			binder_debug(BINDER_DEBUG_TRANSACTION_COMPLETE, "binder: %d:%d BR_TRANSACTION_COMPLETE\n", proc->pid, thread->pid);

			list_del(&w->entry);
			kfree(w);
		} break;
		case BINDER_WORK_NODE: {
			struct binder_node *node = container_of(w, struct binder_node, work);
			uint32_t cmd = BR_NOOP;
			const char *cmd_name;
			int strong = node->internal_strong_refs || node->local_strong_refs;
			int weak = !hlist_empty(&node->refs) || node->local_weak_refs || strong;
			if (weak && !node->has_weak_ref) {
				cmd = BR_INCREFS;
				cmd_name = "BR_INCREFS";
				node->has_weak_ref = 1;
				node->pending_weak_ref = 1;
				node->local_weak_refs++;
			} else if (strong && !node->has_strong_ref) {
				cmd = BR_ACQUIRE;
				cmd_name = "BR_ACQUIRE";
				node->has_strong_ref = 1;
				node->pending_strong_ref = 1;
				node->local_strong_refs++;
			} else if (!strong && node->has_strong_ref) {
				cmd = BR_RELEASE;
				cmd_name = "BR_RELEASE";
				node->has_strong_ref = 0;
			} else if (!weak && node->has_weak_ref) {
				cmd = BR_DECREFS;
				cmd_name = "BR_DECREFS";
				node->has_weak_ref = 0;
			}
			if (cmd != BR_NOOP) {
				if (copy_to_user(current->mm, &cmd, (uint32_t __user *)ptr, sizeof(uint32_t)))
					return -E_FAULT;
				ptr += sizeof(uint32_t);
				if (copy_to_user(current->mm, &node->ptr, (void * __user *)ptr, sizeof(void*)))
					return -E_FAULT;
				ptr += sizeof(void *);
				if (copy_to_user(current->mm, &node->cookie, (void * __user *)ptr, sizeof(void*)))
					return -E_FAULT;
				ptr += sizeof(void *);

				binder_stat_br(proc, thread, cmd);
				binder_debug(BINDER_DEBUG_USER_REFS, "binder: %d:%d %s %d u%p c%p\n", proc->pid, thread->pid, cmd_name, node->debug_id, node->ptr, node->cookie);
			} else {
				list_del_init(&w->entry);
				if (!weak && !strong) {
					binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d:%d node %d u%p c%p deleted\n",proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
					rb_erase(&proc->nodes, &node->rb_node);
					kfree(node);
				} else {
					binder_debug(BINDER_DEBUG_INTERNAL_REFS, "binder: %d:%d node %d u%p c%p state unchanged\n",
						     proc->pid, thread->pid, node->debug_id, node->ptr, node->cookie);
				}
			}
		} break;
		case BINDER_WORK_DEAD_BINDER:
		case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
		case BINDER_WORK_CLEAR_DEATH_NOTIFICATION: {
			struct binder_ref_death *death;
			uint32_t cmd;

			death = container_of(w, struct binder_ref_death, work);
			if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION)
				cmd = BR_CLEAR_DEATH_NOTIFICATION_DONE;
			else
				cmd = BR_DEAD_BINDER;
			if (copy_to_user(current->mm, &cmd, (uint32_t __user *)ptr, sizeof(uint32_t)))
				return -E_FAULT;
			ptr += sizeof(uint32_t);
			if (copy_to_user(current->mm, &death->cookie, (void * __user *)ptr, sizeof(void*)))
				return -E_FAULT;
			ptr += sizeof(void *);
			binder_stat_br(proc, thread, cmd);
			binder_debug(BINDER_DEBUG_DEATH_NOTIFICATION, "binder: %d:%d %s %p\n", proc->pid, thread->pid,
				      cmd == BR_DEAD_BINDER ? "BR_DEAD_BINDER" : "BR_CLEAR_DEATH_NOTIFICATION_DONE", death->cookie);

			if (w->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION) {
				list_del(&w->entry);
				kfree(death);
			} else
			  // TODO: move
				list_move(&w->entry, &proc->delivered_death);
			if (cmd == BR_DEAD_BINDER)
				goto done; /* DEAD_BINDER notifications can cause transactions */
		} break;
		}

		if (!t)
			continue;

		BUG_ON(t->buffer == NULL);
		if (t->buffer->target_node)
		{
			struct binder_node *target_node = t->buffer->target_node;
			tr.target.ptr = target_node->ptr;
			tr.cookie =  target_node->cookie;
			t->saved_priority = task_nice(current);
			if (t->priority < target_node->min_priority &&
			    !(t->flags & TF_ONE_WAY))
				binder_set_nice(t->priority);
			else if (!(t->flags & TF_ONE_WAY) ||
				 t->saved_priority > target_node->min_priority)
				binder_set_nice(target_node->min_priority);
			cmd = BR_TRANSACTION;
		} else {
			tr.target.ptr = NULL;
			tr.cookie = NULL;
			cmd = BR_REPLY;
		}
		tr.code = t->code;
		tr.flags = t->flags;
		tr.sender_euid = t->sender_euid;

		if (t->from) {
			struct proc_struct *sender = t->from->proc->tsk;
			tr.sender_pid = task_tgid_nr_ns(sender, current->nsproxy->pid_ns);
		} else {
			tr.sender_pid = 0;
		}

		tr.data_size = t->buffer->data_size;
		tr.offsets_size = t->buffer->offsets_size;
		tr.data.ptr.buffer = (void *)t->buffer->data + proc->user_buffer_offset;
		tr.data.ptr.offsets = tr.data.ptr.buffer + ROUNDUP(t->buffer->data_size, sizeof(void *));

		if (copy_to_user(current->mm, &cmd, (uint32_t __user *)ptr, sizeof(uint32_t)))
			return -E_FAULT;
		ptr += sizeof(uint32_t);
		if (copy_to_user(current->mm, ptr, &tr, sizeof(tr)))
			return -E_FAULT;
		ptr += sizeof(tr);

//		trace_binder_transaction_received(t);
		binder_stat_br(proc, thread, cmd);
		binder_debug(BINDER_DEBUG_TRANSACTION,
			     "binder: %d:%d %s %d %d:%d, cmd %d size %zd-%zd ptr %p-%p\n", proc->pid, thread->pid,
			     (cmd == BR_TRANSACTION) ? "BR_TRANSACTION" : "BR_REPLY",
			     t->debug_id, t->from ? t->from->proc->pid : 0, t->from ? t->from->pid : 0, cmd,
			     t->buffer->data_size, t->buffer->offsets_size, tr.data.ptr.buffer, tr.data.ptr.offsets);

		list_del(&t->work.entry);
		t->buffer->allow_user_free = 1;
		if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) {
			t->to_parent = thread->transaction_stack;
			t->to_thread = thread;
			thread->transaction_stack = t;
		} else {
			t->buffer->transaction = NULL;
			kfree(t);
		}
		break;
	}

done:

	*consumed = ptr - buffer;
	if (proc->requested_threads + proc->ready_threads == 0 && proc->requested_threads_started < proc->max_threads &&
	    (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) /* the user-space code fails to */
	     /*spawn a new thread if we leave this out */) {
		proc->requested_threads++;
		binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d BR_SPAWN_LOOPER\n", proc->pid, thread->pid);
		if (copy_to_user(current->mm, BR_SPAWN_LOOPER, (uint32_t __user *)buffer, sizeof(uint32_t)))
			return -E_FAULT;
		binder_stat_br(proc, thread, BR_SPAWN_LOOPER);
	}
	return 0;
}

/// CLEAR
static void binder_release_work(list_entry_t *list)
{
	struct binder_work *w;
	while (!list_empty(list)) {
	    // get first entry
		w = to_struct(list_next(list), struct binder_work, entry);
		// delete and reinitialize
		list_del_init(&w->entry);

		switch (w->type) {
		case BINDER_WORK_TRANSACTION: {
			struct binder_transaction *t;

			t = to_struct(&w, struct binder_transaction, work);
			if (t->buffer->target_node && !(t->flags & TF_ONE_WAY))
				binder_send_failed_reply(t, BR_DEAD_REPLY);
		} break;
		case BINDER_WORK_TRANSACTION_COMPLETE: {
			kfree(w);
		} break;
		default:
			break;
		}
	}
}

/// ADD
// thread id compare
int keycompare_rbtree_binder_thread_pid(rb_node *node, void *key)
{
    int pid = ((struct proc_struct*)key)->pid;
    int n_pid = to_struct(node, struct binder_thread, rb_node_)->pid;

    if (n_pid == pid)
        return 0;
    else if (n_pid < pid)
        return -1;
    else
        return 1;
}

/// ADD
// thread id compare
int compare_rbtree_binder_thread_pid(rb_node *node1, rb_node *node2)
{
    int pid1 = to_struct(node1, struct binder_thread, rb_node_)->pid;
    int pid2 = to_struct(node2, struct binder_thread, rb_node_)->pid;

    if (pid1 == pid2)
        return 0;
    else if (pid1 < pid2)
        return -1;
    else
        return 1;
}


/// CLEAR
static struct binder_thread *binder_get_thread(struct binder_proc *proc)
{
	struct binder_thread *thread = NULL;
	//rb_node *parent = NULL;
	//rb_node **p = &proc->threads.root;

    // find rbtree node
	rb_node* p = rb_search(proc->threads, keycompare_rbtree_binder_thread_pid, current->pid);

	if (p == NULL) // no found, create new
	{
		thread = kzalloc(sizeof(*thread));
		if (thread == NULL)
			return NULL;

		thread->proc = proc;
		thread->pid = current->pid;
		wait_queue_init(&thread->wait);
		list_init(&thread->todo);

        // link to node
        rb_insert(proc->threads, &thread->rb_node_);

		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		thread->return_error = BR_OK;
		thread->return_error2 = BR_OK;
	}
	else // found
        thread = to_struct(parent, struct binder_thread, rb_node_);

	return thread;
}

/// CLEAR
static int binder_free_thread(struct binder_proc *proc, struct binder_thread *thread)
{
	struct binder_transaction *t;
	struct binder_transaction *send_reply = NULL;
	int active_transactions = 0;

	rb_delete(proc->threads, &thread->rb_node);
	t = thread->transaction_stack;
	if (t && t->to_thread == thread)
		send_reply = t;

    // traverse all related transactions
	while (t) {
		active_transactions++;
		binder_debug(BINDER_DEBUG_DEAD_TRANSACTION,
			     "binder: release %d:%d transaction %d "
			     "%s, still active\n", proc->pid, thread->pid,
			     t->debug_id,
			     (t->to_thread == thread) ? "in" : "out");

		if (t->to_thread == thread) {
			t->to_proc = NULL;
			t->to_thread = NULL;
			if (t->buffer) {
				t->buffer->transaction = NULL;
				t->buffer = NULL;
			}
			t = t->to_parent;
		} else if (t->from == thread) {
			t->from = NULL;
			t = t->from_parent;
		} else
			panic("Binder_free_thread Error.");
	}

	if (send_reply)
		binder_send_failed_reply(send_reply, BR_DEAD_REPLY);
	binder_release_work(&thread->todo);
	kfree(thread);
	return active_transactions;
}

/// MOD TODO: poll support in ucore
static unsigned int binder_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread = NULL;
	int wait_for_proc_work;

	binder_lock();

	thread = binder_get_thread(proc);

	wait_for_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo) && thread->return_error == BR_OK;

	binder_unlock();

	if (wait_for_proc_work) {
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
//		poll_wait(filp, &proc->wait, wait);
		if (binder_has_proc_work(proc, thread))
			return POLLIN;
	} else {
		if (binder_has_thread_work(thread))
			return POLLIN;
//		poll_wait(filp, &thread->wait, wait);
		if (binder_has_thread_work(thread))
			return POLLIN;
	}
	return 0;
}

/// CLEAR non_block
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret;
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread;
	unsigned int size = _IOC_SIZE(cmd);
	void *ubuf = (void*)arg;

	/*cprintf(KERN_INFO "binder_ioctl: %d:%d %x %lx\n", proc->pid, current->pid, cmd, arg);*/

	ret = wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	if (ret)
		goto err_unlocked;

	binder_lock();
	thread = binder_get_thread(proc);
	if (thread == NULL) {
		ret = -E_NOMEM;
		goto err;
	}

	switch (cmd) {
	case BINDER_WRITE_READ: {
		struct binder_write_read bwr;
		// check command size
		if (size != sizeof(struct binder_write_read)) {
			ret = -E_INVAL;
			goto err;
		}
		// copy to kernel space, for return , must be writable
		if (copy_from_user(current->mm, &bwr, ubuf, sizeof(bwr), 1)) {
			ret = -E_FAULT;
			goto err;
		}
		binder_debug(BINDER_DEBUG_READ_WRITE,
			     "binder: %d:%d write %ld at %08lx, read %ld at %08lx\n",
			     proc->pid, thread->pid, bwr.write_size, bwr.write_buffer,
			     bwr.read_size, bwr.read_buffer);

        // write
		if (bwr.write_size > 0) {
			ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
			if (ret < 0) {
				bwr.read_consumed = 0;
				if (copy_to_user(current->mm, ubuf, &bwr, sizeof(bwr)))
					ret = -E_FAULT;
				goto err;
			}
		}
		// read
		if (bwr.read_size > 0) {
		    // TODO: block io, default BLOCKIO
			// filp->f_flags & O_NONBLOCK);
			ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, 0);
			if (!list_empty(&proc->todo))
			// TODO: wake up
				wake_up_interruptible(&proc->wait);
			if (ret < 0) {
				if (copy_to_user(current->mm, ubuf, &bwr, sizeof(bwr)))
					ret = -E_FAULT;
				goto err;
			}
		}
		binder_debug(BINDER_DEBUG_READ_WRITE,
			     "binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",
			     proc->pid, thread->pid, bwr.write_consumed, bwr.write_size,
			     bwr.read_consumed, bwr.read_size);
		if (copy_to_user(current->mm, ubuf, &bwr, sizeof(bwr))) {
			ret = -E_FAULT;
			goto err;
		}
		break;
	}
	case BINDER_SET_MAX_THREADS:
		if (copy_from_user(current->mm, &proc->max_threads, ubuf, sizeof(proc->max_threads), 0)) {
			ret = -E_INVAL;
			goto err;
		}
		break;
	case BINDER_SET_CONTEXT_MGR:
		if (binder_context_mgr_node != NULL) {
			cprintf(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
			ret = -E_BUSY;
			goto err;
		}
		if (binder_context_mgr_uid != -1) {
		    // TODO: uid...
			//if (binder_context_mgr_uid != current->cred->euid) {
			//	cprintf(KERN_ERR "binder: BINDER_SET_"
			//	       "CONTEXT_MGR bad uid %d != %d\n",
			//	       current->cred->euid,
			//	       binder_context_mgr_uid);
			//	ret = -E_PERM;
			//	goto err;
			//}
		} else
            // TODO: uid, currently UID=0
			//binder_context_mgr_uid = current->cred->euid;
			binder_context_mgr_uid = 0;

		binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
		if (binder_context_mgr_node == NULL) {
			ret = -E_NOMEM;
			goto err;
		}
		binder_context_mgr_node->local_weak_refs++;
		binder_context_mgr_node->local_strong_refs++;
		binder_context_mgr_node->has_strong_ref = 1;
		binder_context_mgr_node->has_weak_ref = 1;
		break;
	case BINDER_THREAD_EXIT:
		binder_debug(BINDER_DEBUG_THREADS, "binder: %d:%d exit\n",
			     proc->pid, thread->pid);
		binder_free_thread(proc, thread);
		thread = NULL;
		break;
	case BINDER_VERSION:
	{
		if (size != sizeof(struct binder_version)) {
			ret = -E_INVAL;
			goto err;
		}
		// replace put_user by copy_to_user
        register signed long protocol_version_temp = BINDER_CURRENT_PROTOCOL_VERSION;
		if (copy_to_user(current->mm, &((struct binder_version *)ubuf)->protocol_version, &protocol_version_temp, sizeof(protocol_version_temp))) {
			ret = -E_INVAL;
			goto err;
		}
		break;
	}
	default:
		ret = -E_INVAL;
		goto err;
	}
	ret = 0;
err:
	if (thread)
		thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
	binder_unlock();
	wait_event_interruptible(binder_user_error_wait, binder_stop_on_user_error < 2);
	if (ret && ret != -E_RESTARTSYS)
		cprintf(KERN_INFO "binder: %d:%d ioctl %x %lx returned %d\n", proc->pid, current->pid, cmd, arg, ret);
err_unlocked:
//	trace_binder_ioctl_done(ret);
	return ret;
}

/// CLEAR
static void binder_vma_open(struct vma_struct* vma)
{
	struct binder_proc *proc = vma->mfile.file->_private_data;
	binder_debug(BINDER_DEBUG_OPEN_CLOSE,
		     "binder: %d open vm area %lx-%lx (%ld K) vma %lx pagep\n",
		     proc->pid, vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags);
}

/// CLEAR
static void binder_vma_close(struct vma_struct* vma)
{
	struct binder_proc *proc = vma->mfile.file->_private_data;
	binder_debug(BINDER_DEBUG_OPEN_CLOSE,
		     "binder: %d close vm area %lx-%lx (%ld K) vma %lx pagep\n",
		     proc->pid, vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags);
	proc->vma = NULL;
	proc->vma_vm_mm = NULL;
	binder_defer_work(proc, BINDER_DEFERRED_PUT_FILES);
}

//static struct vm_operations_struct binder_vm_ops = {
//	.open = binder_vma_open,
//	.close = binder_vma_close,
//};

/// CLEAR
static int binder_mmap(struct file *filp, struct vma_struct *vma)
{
	int ret;
	struct binder_proc *proc = filp->private_data;
	const char *failure_string;
	struct binder_buffer *buffer;

    // maximum size 4M
	if ((vma->vm_end - vma->vm_start) > SZ_4M)
		vma->vm_end = vma->vm_start + SZ_4M;

	binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_mmap: %d %lx-%lx (%ld K) vma %lx pagep %lx\n",
		     proc->pid, vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / SZ_1K, vma->vm_flags
	/*, (unsigned long)pgprot_val(vma->vm_page_prot)*/);

    // check vma flags, ??? TODO:
//	if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) {
//		ret = -E_PERM;
//		failure_string = "bad vm_flags";
//		goto err_bad_arg;
//	}
//	vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;

    // check already mapped
	down(&binder_mmap_lock);
	if (proc->buffer) {
		ret = -EBUSY;
		failure_string = "already mapped";
		goto err_already_mapped;
	}

    // get highmem
//	area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
//	if (area == NULL) {
//		ret = -E_NOMEM;
//		failure_string = "get_vm_area";
//		goto err_get_vm_area_failed;
//	}
    // FIXME: currently prealloc
    // TODO: ??? check align???
    struct Page* page_area = alloc_pages(ROUNDUP_DIV(vma->vm_end - vma->vm_start, PGSIZE));
    if (page_area == NULL) {
		ret = -E_NOMEM;
		failure_string = "get_vm_area";
		goto err_get_vm_area_failed;
	}
    proc->buffer_page = page_area;
    void* area = page2kva(page_area);

	proc->buffer = area;
	proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;
	up(&binder_mmap_lock);

    // alloc page management struct
	proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PGSIZE));
	if (proc->pages == NULL) {
		ret = -E_NOMEM;
		failure_string = "alloc page array";
		goto err_alloc_pages_failed;
	}
	proc->buffer_size = vma->vm_end - vma->vm_start;

    // where is these ??
//	vma->vm_ops = &binder_vm_ops;
	vma->mfile.file->private_data = proc;

    // alloc phy space, currently do nothing
	if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PGSIZE, vma)) {
		ret = -E_NOMEM;
		failure_string = "alloc small buf";
		goto err_alloc_small_buf_failed;
	}

	buffer = proc->buffer;
	list_init(&proc->buffers);
	list_add(&proc->buffers, &buffer->entry);
	buffer->free = 1;
	binder_insert_free_buffer(proc, buffer);
	proc->free_async_space = proc->buffer_size / 2;
	barrier();

	proc->files = proc->tsk->fs_struct;

	proc->vma = vma;
	proc->vma_vm_mm = vma->vm_mm;

	cprintf(KERN_INFO "binder_mmap: %d %lx-%lx maps %p\n", proc->pid, vma->vm_start, vma->vm_end, proc->buffer);
	return 0;

err_alloc_small_buf_failed:
	kfree(proc->pages);
	proc->pages = NULL;
err_alloc_pages_failed:
	down(&binder_mmap_lock);
	// TODO:
	// free_page_area(proc->buffer);
	// vfree(proc->buffer);
	proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
	up(&binder_mmap_lock);
err_bad_arg:
	cprintf(KERN_ERR "binder_mmap: %d %lx-%lx %s failed %d\n", proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
	return ret;
}

/// CLEAR_rbtree
static int binder_open(struct inode *nodp);//, struct file *filp)
{
	// HACKCODE

	struct binder_proc *proc;

	binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_open: %d\n", current->pid);

	proc = kzalloc(sizeof(*proc));

	if (proc == NULL)
		return -E_NOMEM;
	proc->tsk = current;
	list_init(&proc->todo);
	waitqueue_init(&proc->wait);
	proc->default_priority = task_nice(current);
	// init rbtree
	proc->threads = rb_tree_create(compare_rbtree_binder_thread_pid);
	// TODO: init other rbtree

	binder_lock();

	// replace hlist_add_head by list_add ???
	list_add(&binder_procs, &proc->proc_node);
	// TODO: group_leader
        proc->pid = current->group_leader->pid;

	list_init(&proc->delivered_death);
	filp->private_data = proc;

	binder_unlock();

	return 0;
}

/// CLEAR
static int binder_flush(struct file *filp)
{
	struct binder_proc *proc = filp->private_data;

	binder_defer_work(proc, BINDER_DEFERRED_FLUSH);

	return 0;
}

/// CLEAR
static void binder_deferred_flush(struct binder_proc *proc)
{
	int wake_count = 0;
	for (struct rb_node* n = rb_node_first(&proc->threads); n != NULL; n = rb_node_next(&proc->threads, n))
	{
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
		if (thread->looper & BINDER_LOOPER_STATE_WAITING) {
			wake_up_interruptible(&thread->wait);
			wake_count++;
		}
	}
	wake_up_interruptible_all(&proc->wait);

	binder_debug(BINDER_DEBUG_OPEN_CLOSE, "binder_flush: %d woke %d threads\n", proc->pid, wake_count);
}

/// CLEAR
static int binder_release(struct inode *nodp, struct file *filp)
{
	struct binder_proc *proc = filp->private_data;
	binder_defer_work(proc, BINDER_DEFERRED_RELEASE);

	return 0;
}

/// CLEAR
static void binder_deferred_release(struct binder_proc *proc)
{
	struct hlist_node *pos;
	struct binder_transaction *t;
	int threads, nodes, incoming_refs, outgoing_refs, buffers, active_transactions, page_count;

	BUG_ON(proc->vma);
	BUG_ON(proc->files);

	list_del(&proc->proc_node);
	if (binder_context_mgr_node && binder_context_mgr_node->proc == proc) {
		binder_debug(BINDER_DEBUG_DEAD_BINDER,
			     "binder_release: %d context_mgr_node gone\n", proc->pid);
		binder_context_mgr_node = NULL;
	}

	threads = 0;
	active_transactions = 0;
	while ((struct rb_node* n = rb_node_first(&proc->threads))) {
		struct binder_thread *thread = rb_entry(n, struct binder_thread, rb_node);
		threads++;
		active_transactions += binder_free_thread(proc, thread);
	}
	nodes = 0;
	incoming_refs = 0;
	while ((struct rb_node* n = rb_first(&proc->nodes)))
	{
		struct binder_node *node = rb_entry(n, struct binder_node, rb_node);

		nodes++;
		rb_erase(&proc->nodes, &node->rb_node);
		list_del_init(&node->work.entry);
		if (list_empty(&node->refs))
			kfree(node);
		else
		{
			struct binder_ref *ref;
			int death = 0;

			node->proc = NULL;
			node->local_strong_refs = 0;
			node->local_weak_refs = 0;
			hlist_add_head(&node->dead_node, &binder_dead_nodes);

			hlist_for_each_entry(ref, pos, &node->refs, node_entry)
			{
				incoming_refs++;
				if (ref->death)
				{
					death++;
					if (list_empty(&ref->death->work.entry))
					{
						ref->death->work.type = BINDER_WORK_DEAD_BINDER;
						list_add_tail(&ref->death->work.entry, &ref->proc->todo);
						wake_up_interruptible(&ref->proc->wait);
					} else
						BUG();
				}
			}
			binder_debug(BINDER_DEBUG_DEAD_BINDER,
				     "binder: node %d now dead, refs %d, death %d\n", node->debug_id, incoming_refs, death);
		}
	}
	outgoing_refs = 0;
	while ((struct rb_node* n = rb_node_first(&proc->refs_by_desc)))
	{
		struct binder_ref *ref = rb_entry(n, struct binder_ref, rb_node_desc);
		outgoing_refs++;
		binder_delete_ref(ref);
	}
	binder_release_work(&proc->todo);
	buffers = 0;

	while ((struct rb_node* n = rb_node_first(&proc->allocated_buffers)))
	{
		struct binder_buffer *buffer = rb_entry(n, struct binder_buffer, rb_node);
		t = buffer->transaction;
		if (t)
		{
			t->buffer = NULL;
			buffer->transaction = NULL;
			cprintf(KERN_ERR "binder: release proc %d, transaction %d, not freed\n", proc->pid, t->debug_id);
			/*BUG();*/
		}
		binder_free_buf(proc, buffer);
		buffers++;
	}

	page_count = 0;
	if (proc->pages)
	{
		int i;
		for (i = 0; i < proc->buffer_size / PGSIZE; i++)
		{
			if (proc->pages[i])
			{
				void *page_addr = proc->buffer + i * PGSIZE;
				binder_debug(BINDER_DEBUG_BUFFER_ALLOC,
					     "binder_release: %d: page %d at %p not freed\n", proc->pid, i, page_addr);
				
				// FIXME: TODO: vmalloc
				// unmap_kernel_range((unsigned long)page_addr, PGSIZE);
				// __free_page(proc->pages[i]);
				page_count++;
			}
		}
		kfree(proc->pages);
		// FIXME: TODO: 
		// vfree(proc->buffer);
	}

	put_task_struct(proc->tsk);

	binder_debug(BINDER_DEBUG_OPEN_CLOSE,
		     "binder_release: %d threads %d, nodes %d (ref %d), refs %d, active transactions %d, buffers %d, pages %d\n",
		     proc->pid, threads, nodes, incoming_refs, outgoing_refs, active_transactions, buffers, page_count);

	kfree(proc);
}

/// MOD FIXME: work_queue
static void binder_deferred_func_tmp(struct binder_proc* proc, int defer)//struct work_struct *work)
{
	struct binder_proc *proc;
	struct fs_struct *files;

	int defer;
	do {
		binder_lock();
//		mutex_lock(&binder_deferred_lock);
//		if (!hlist_empty(&binder_deferred_list)) {
//			proc = hlist_entry(binder_deferred_list.first,
//					struct binder_proc, deferred_work_node);
//			hlist_del_init(&proc->deferred_work_node);
//			defer = proc->deferred_work;
//			proc->deferred_work = 0;
//		} else {
//			proc = NULL;
//			defer = 0;
//		}
//		mutex_unlock(&binder_deferred_lock);

		files = NULL;
		if (defer & BINDER_DEFERRED_PUT_FILES) {
			files = proc->files;
			if (files)
				proc->files = NULL;
		}

		if (defer & BINDER_DEFERRED_FLUSH)
			binder_deferred_flush(proc);

		if (defer & BINDER_DEFERRED_RELEASE)
			binder_deferred_release(proc); /* frees proc */

		binder_unlock();
		if (files)
			put_fs(files);
	} while (proc);
}
//static DECLARE_WORK(binder_deferred_work, binder_deferred_func);

/// CLEAR ??? defered workss
static void
binder_defer_work(struct binder_proc *proc, enum binder_deferred_state defer)
{
	mutex_lock(&binder_deferred_lock);
// TODO:
//	proc->deferred_work |= defer;
//	if (hlist_unhashed(&proc->deferred_work_node)) {
//		hlist_add_head(&proc->deferred_work_node,
//				&binder_deferred_list);
//		queue_work(binder_deferred_workqueue, &binder_deferred_work);
//	}
	binder_deferred_work_tmp(proc, defer);
	mutex_unlock(&binder_deferred_lock);
}


static const char *binder_return_strings[] = {
	"BR_ERROR",
	"BR_OK",
	"BR_TRANSACTION",
	"BR_REPLY",
	"BR_ACQUIRE_RESULT",
	"BR_DEAD_REPLY",
	"BR_TRANSACTION_COMPLETE",
	"BR_INCREFS",
	"BR_ACQUIRE",
	"BR_RELEASE",
	"BR_DECREFS",
	"BR_ATTEMPT_ACQUIRE",
	"BR_NOOP",
	"BR_SPAWN_LOOPER",
	"BR_FINISHED",
	"BR_DEAD_BINDER",
	"BR_CLEAR_DEATH_NOTIFICATION_DONE",
	"BR_FAILED_REPLY"
};

static const char *binder_command_strings[] = {
	"BC_TRANSACTION",
	"BC_REPLY",
	"BC_ACQUIRE_RESULT",
	"BC_FREE_BUFFER",
	"BC_INCREFS",
	"BC_ACQUIRE",
	"BC_RELEASE",
	"BC_DECREFS",
	"BC_INCREFS_DONE",
	"BC_ACQUIRE_DONE",
	"BC_ATTEMPT_ACQUIRE",
	"BC_REGISTER_LOOPER",
	"BC_ENTER_LOOPER",
	"BC_EXIT_LOOPER",
	"BC_REQUEST_DEATH_NOTIFICATION",
	"BC_CLEAR_DEATH_NOTIFICATION",
	"BC_DEAD_BINDER_DONE"
};

static const char *binder_objstat_strings[] = {
	"proc",
	"thread",
	"node",
	"ref",
	"death",
	"transaction",
	"transaction_complete"
};

/// MOD
static int binder_init(void)
{
	int ret;

// TODO:
//	binder_deferred_workqueue = create_singlethread_workqueue("binder");
//	if (!binder_deferred_workqueue)
//		return -E_NOMEM;

	// init mutex
	sem_init(binder_main_lock, 1);
	sem_init(binder_deferred_lock, 1);
	sem_init(binder_mmap_lock, 1);

	// init (h)list
	list_init(&binder_procs);
	list_init(&binder_deferred_list);
	list_init(&binder_dead_nodes);

	// init wait queue
	wait_queue_init(&binder_user_error_wait);


	return ret;
}

// interface for device

/// wrap for interface
static int
wrap_binder_open(struct device *dev, uint32_t open_flags)
{
    return binder_open(open_flags, binder_filp);
}

static int
wrap_binder_close(struct device *dev)
{
    return binder_close(binder_filp);
}

static int
wrap_binder_io(struct device *dev, struct iobuf *iob, bool write)
{
    return -E_INVAL;
}

static int
wrap_binder_ioctl(struct device *dev, int op, void *data)
{
    return -E_INVAL;
}

void* wrap_binder_mmap(struct device *dev, void *addr, size_t len, int unused1, int unused2, size_t off)
{
  return NULL;
}

/// MOD
static void
binder_device_init(struct device *dev)
{
    memset(dev, 0, sizeof(*dev));
    dev->d_blocks = 0;
    dev->d_blocksize = 1;
    dev->d_open = wrap_binder_open;
    dev->d_close = wrap_binder_close;
    dev->d_io = wrap_binder_io;
    dev->d_linux_mmap = wrap_binder_mmap;
    dev->d_ioctl = wrap_binder_ioctl;
    
    // TODO: not support in ucore yet
//	.poll = binder_poll,
//	.flush = binder_flush,
//	.release = binder_release,

    binder_init();
}

/// CLEAR
void
dev_init_binder(void)
{
    struct inode *node;
    if ((node = dev_create_inode()) == NULL)
        panic("binder: dev_create_node.\n");

    binder_device_init(vop_info(node, device));

    int ret;
    if ((ret = vfs_add_dev("binder", node, 0)) != 0)
        panic("binder: vfs_add_dev: %e.\n", ret);
}
