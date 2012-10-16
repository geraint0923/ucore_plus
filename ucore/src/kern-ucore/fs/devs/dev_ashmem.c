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


struct ashmem_area {
	char name[ASHMEM_FULL_NAME_LEN];
	struct list_entry_t unpinned_list;
	struct file *file;
	size_t size;
	unsigned long prot_mask;
};

struct ashmem_range {
	struct list_entry_t lru;
	struct list_entry_t unpinned;
	struct ashmem_area *asma;
	size_t pgstart;
	size_t pgend;
	unsigned int purged;
};

static int
ashmem_open(struct device *dev, uint32_t open_flags) {
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

static void 
ashmem_device_init(struct device *dev) {
	memset(dev, 0, sizeof(*dev));
	dev->d_blocks = 0;
	dev->d_blocksize = 1;
	dev->d_open = ashmem_open;
	dev->d_close = ashmem_close;
	dev->d_io = ashmem_io;
	dev->d_ioctl = ashmem_ioctl;
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
