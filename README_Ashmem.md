1. What is ashmem?
ASHMEM means Anonymous Share Memory, which is implemented in Android to manage share memory in the kernel more efficiently.
In omap kernel provided by Google Inc., the implementation of ashmem is located in:
include/linux/ashmem.h
kernel/mm/ashmem.c
And these are what we can refer to.

2. How does ashmem work?
Ashmem uses pin/unpin to help kernel manage the allocation and recycling in kernel.
We assume that you get some memory from kernel using /dev/ashmem, then when that memory which you get from ashmem will never be used in the future, then you are able to unpin it so that the memory shrinker implemented by ashmem will help recycle it.

3. What if compiling ashmem from Android source code with DDE?
In fact, we could not compile ashmem.c with the current version of DDE which is still a alpha version.
Here is something to do to compile it with DDE:
	(1) Lots of unimplemented API in kernel.
	(2) Some structs required by the origin ashmem driver

4. How to implement ashmem in ucore_plus?
We will try to implement an easy ashmem in ucore_plus, which could help initialize the dalvikvm.
Two of the most important struct in ashmem:

struct ashmem_area {
	char name[ASHMEM_FULL_NAME_LEN];
	struct list_head unpinned_list;
	struct file *file;
	size_t size;
	unsigned long prot_mask;
};

struct ashmem_range {
	struct list_head lru;
	struct list_head unpinned;
	struct ashmem_area *asma;
	size_t pgstart;
	size_t pgend;
	unsigned int purged;
};

