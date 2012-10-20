#include <types.h>
#include <dev.h>
#include <vfs.h>
#include <iobuf.h>
#include <inode.h>
#include <error.h>
#include <assert.h>
#include <stdio.h>
#include <error.h>
#include <shmem.h>
#include <sem.h>
#include <kio.h>

#define ASHMEM_NAME_LEN		256
#define ASHMEM_NAME_DEF		"dev/ashmem"

#define ASHMEM_NOT_PURGED	0
#define ASHMEM_WAS_PURGED	1

#define ASHMEM_IS_UNPINNED	0
#define ASHMEM_IS_PINNED	1

#define ASHMEM_NAME_PREFIX	"dev/ashmem/"
#define ASHMEM_NAME_PREFIX_LEN	(sizeof(ASHMEM_NAME_PREFIX)-1)
#define ASHMEM_FULL_NAME_LEN	(ASHMEM_NAME_LEN + ASHMEM_NAME_PREFIX_LEN)

struct ashmem_pin {
	uint32_t offset;
	uint32_t len;
};

#define __ASHMEMIOC		0x77

#define ASHMEM_SET_NAME     _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME     _IOR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE     _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE     _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK    _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK    _IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN      _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN        _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS   _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)


struct ashmem_area{
	char name[ASHMEM_FULL_NAME_LEN];
	list_entry_t unpinned_list;
	struct file *file;
	size_t size;
	unsigned long prot_mask;
};

struct ashmem_range {
	list_entry_t lru;
	list_entry_t unpinned;
	struct ashmem_area *asma;
	size_t pgstart;
	size_t pgend;
	unsigned int purged;
};




// definea mutex for ashmem
static DEFINE_MUTEX(ashmem_mutex);

#define range_size(range) \
	((range)->pgend - (range)->pgstart + 1)

#define range_on_lru(range) \
	((range)->purged == ASHMEM_NOT_PURGED)

#define page_range_subsumes_range(range, start, end) \
	(((range)->pgstart >= (start)) && ((range)->pgend <= (end)))

#define page_range_subsumed_by_range(range, start, end) \
	(((range)->pgstart <= (start)) && ((range)->pgend >= (end)))

#define page_in_range(range, page) \
	(((range)->pgstart <= (page)) && ((range)->pgend >= (page)))

#define page_range_in_range(range, start, end) \
	(page_in_range(range, start) || page_in_range(range, end) || \
	 page_range_subsumes_range(range, start, end))

#define range_before_page(range, page) \
	((range)->pgend < (page))

#define PROT_MASK       (PROT_EXEC | PROT_READ | PROT_WRITE)


static inline void lru_addr(struct ashmem_range *range) {
	list_add_tail(&range->lru, ashmem_lru_list);
	lru_count += range_size(range);
}

static inline void lru_del(struct ashmem_range *range) {
	list_del(&range->lru);
	lru_count -= range_size(range);
}



static int
ashmem_open(struct device *dev, uint32_t open_flags) {
	kprintf("That is ashmem!!!");
	return 0;
}

static int
ashmem_close(struct device *dev) {
	return 0;
}

static int
ashmem_io(struct device *dev, struct iobuf *iob, bool write) {
	return 0;
}

static int 
ashmem_ioctl(struct device *dev, int op, void *data) {
	return 0;
}

static int
ashmem_mmap(struct device *dev, void *addr, size_t len, int prot, int flag, size_t off) {
}



static void 
ashmem_device_init(struct device *dev) {
	memset(dev, 0, sizeof(*dev));
	dev->d_blocks = 0;
	dev->d_blocksize = 1;
	dev->d_open = ashmem_open;
	dev->d_close = ashmem_close;
	dev->d_io = ashmem_io;
	dev->d_ioctl = ashmem_ioctl;
	dev->d_linux_mmap = ashmem_mmap;
}

void 
dev_init_ashmem(void) {
	struct inode *node;
	if((node = dev_create_inode()) == NULL) {
		panic("null: dev_create_node.\n");
	}
	ashmem_device_init(vop_info(node, device));
	
	int ret;
	if((ret = vfs_add_dev("ashmem", node, 0)) != 0) {
		panic("ashmem: vfs_add_dev: %e.\n", ret);
	}
}
