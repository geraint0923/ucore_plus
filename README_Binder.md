Binder on UCore
================================
Report 1
--------------------------------

## What is Binder ##
Binder是一种跨进程的通信机制（IPC），最早是基于OpenBinder，后来在Android上被广泛应用。
OpenBinder最先是由Be Inc.开发的，接着Palm Inc.也跟着使用。现在OpenBinder的作者Dianne Hackborn就是在Google工作，负责Android平台的开发工作。

Binder是一种基于Server-Client模式的通信机制，包括阻塞和非阻塞通信。在基本的通信协议基础上，它提供RPC的机制。

## Binder的结构 ##
![hello](http://hi.csdn.net/attachment/201107/19/0_13110996490rZN.gif)
Binder共有四部分组成，分别是Client，Server，Service Manager和Driver。其中只有Driver在内核态，其他三个部分在用户态，他们的职能如下：

* Server是服务的提供者，而Client是服务的使用者。Client远程调用Server上的函数与方法。
* Driver提供调用的接口并维护秩序。所有的调用操作都是通过对`/dev/binder`设备文件的`ioctl`函数完成的。
* Service Manager是一个特殊的Server，提供对Service的一些管理功能。它在系统启动时一直存在，并且有固定的Service ID可以供所有Client直接访问。

## Binder on Ucore ##
简单起见，下面称Binder on Ucore为**uBinder**。

移植需要对Binder的4个部分同时进行。鉴于Yangyang的工作，BionicLibC已经基本可以运行，这样在用户态的三个部分理论上实现源码无修改的运行（可能有潜在Bug）。唯一需要注意两点：

* 据Yangyang据Chenyuheng，Ucore的ARM框架的代码中，程序初始加载点在0x30008000？处，而不是0x00008000？处，需要修改链接的参数。
* binder的设备文件名是`/dev/binder`，而在Ucore中并不支持这样的设备文件名，需要全部替换成`binder:`。

> 这部分已经转移给Chenzhuwei来做。

至于关键的Driver部分，有两种方案可以做，分别是基于DDE的方案和独立实现的方案。

### 基于DDE ###
基于Chengyuheng的DDE框架，我尝试移植了Driver部分。一共出现了39个Unreferenced functions & variables，经我整理有这几类没有实现：

```
lock_task_sighand
expand_files
__set_open_fd
__set_close_on_exec
__clear_close_on_exec
__clear_open_fd
__clear_close_on_exec
filp_close
can_nice
task_nice
set_user_nice
get_task_mm
down_write
pgprot_kernel
__alloc_pages_internal
map_vm_area
vm_insert_page
mmput
zap_page_range
unmap_kernel_range
__free_pages
up_write
contig_page_data
fget
fput
prepare_to_wait_exclusive
abort_exclusive_wait
task_tgid_nr_ns
get_vm_area
cacheid
get_files_struct
vfree
__put_task_struct
rb_insert_color
rb_erase
rb_first
rb_next
```

* Red-black Tree 相关的方法。Ucore中已经有了红黑树，但是和linux的接口不同（ucore的红黑树比linux接口少，但是使用更加方便）。
* 线程优先级相关的方法。Ucore目前没有相关的支持。
* 内存分配管理的高地址部分。vmalloc没有实现。
* File struct 相关的一些操作。
* Sequence File
* Workqueue
* wait_event
* etc...

### 重新实现 ###
即能加深我们对于系统和binder的理解，又能简化代码的实现。

## Driver 结构 ##
通信模式

## 内存管理 ##
### 内存映射 ###
任何使用binder进行通信的程序都必须要预先使用驱动的mmap方法分配一块缓冲区域。这块区域主要用于接收缓冲区，是binder效率的关键体现。

普通的IPC机制，除了 shared memory 这种被动的方式，包括socket等待，都需要两次的内存拷贝，即用于发送的数据被驱动拷贝到内核缓冲区中，再拷贝到接收方的缓冲区中。这样有两个缺点：

1. 效率低。需要有两次的内存拷贝，而“拷贝到内核”本身没有任何意义。
2. 空间浪费。接收方并不知道数据的大小，所以只能获取与最大可能相同大小的缓冲区。这一点在Server同时处理多个Client请求的时候显得更加明显。

Binder为了改善这两点，采用了驱动和接受方共享内存的机制。即驱动的一块内核内存空间和接收方的一块用户态内存空间映射的是同样的物理页。这操作就是使用mmap方法完成的。所以mmap方法仅仅只能调用一次对每个binder fd。

在通信的时候，内核将发送方发送的数据拷贝到内核的缓冲区中，并通知接受方数据在用户态映射的地址和大小，就完成了数据传输的过程。当然，驱动会对数据做一些处理。

### 内存管理 ###
缓冲区的大小作为mmap的参数被传入。binder驱动限制缓冲区的最大大小为4MB。每个进程的缓冲区会被该服务的所有binder transaction所共享，所以在binder驱动内部有管理缓冲区的算法，使用的是Best-fit算法。接收缓冲区的分配是由驱动完成的，对应的，驱动提供方法释放分配的缓冲区。

缓冲区的虚内存映射是开始就建立的，但是物理空间是按需逐个Page分配的。

### uBinder ###
内核使用的缓冲区空间实在3G+896M以上的高端虚拟内存。ucore不支持`vmalloc`等用于不连续内核分配的函数。所以目前的解决方案是使用`kmalloc`在内核分配一段空间（因为空间很大，实际用的是`alloc_pages`）。再将这一段内核的连续地址映射到用户空间上。

> 但是目前遇到的问题是ucore仅仅支持单个Page的映射到虚拟内存，然而使用`alloc_pages`分配到的是一段连续的物理内存，而且仅仅获取了开头的Page指针。

> 我的疑问是这一段被分配的内存的Page结构每一个Page都被初始化ref=0，是么？这样就可以将这些Page逐个插入，删除时也不会有问题。不然在进程被杀死或者删除的时候会有内存的混乱出现。

binder_android使用先分配一段highmem虚拟空间，再分配若干物理页，将这些物理页和highmem合并在一起。
我们实现中没有highmem，所以目前简化为分配连续的kernel物理地址。
### about Insert_Page


## 实现细节 ##
### list 与 hlist ###
linux中有hlist，即hash_list结构。与普通的双向链表list相比，节约了表头的空间。表头定义如下：
```
typedef struct hlist_head {
    struct hlist_node *first;
} hlist_head;
```
```
struct list_head {
	struct list_head *next, *prev;
};
```
可以看出hlist比list少了指向尾部的指针。这主要针对的是hash表会有大量的表头出现，而每个链表的长度其实很小这个特点，达到节约内存的目的。

* 对于uBinder，目前机械的替换hlist为list，无视内存损失。

### 非阻塞模式 ###
binder支持block和unblock两种通信模式，如前所述。

> 有待确认实际的应用有没有使用两种模式。

因为ucore本身在文件open的函数中和file结构没有NON_BLOCK的flag，所以目前只有BLOCK模式。

> 有待添加NON\_BLOCK的file flag

### 进程优先级变更 ###
在线程迁移技术中用到，如前所述。ucore没有支持，况且对于正确性不是很重要。暂不考虑实现。

是不是在有图形界面后，或者是音乐播放后会考虑到响应速度问题而需要呢？

> 有待添加nice和set_nice等函数

### /proc ###
binder在/proc/binder中对每个binder建立了节点，并将一些状态信息输出到其中。
ucore离/proc还远呢，果断全部删掉。

### VFS的接口不足 ###
// TODO:

### security context of a task ###
1. 用于确认非法进程不会调用BINDER_SET_CONTEXT_MGR，目前已关闭认证，仅留下BINDER_SET_CONTEXT_MGR只能有效调用一次这个认证。UID = 0。

### `put_user` 和 `get_user` ###
用于内核从用户态空间写入和读取小数据（小于8个字节）。ucore没有实现，我也不想移动。
被`copy_to_user`和`copy_from_user`替换，有少许性能损失。

### rb_tree
// TODO:
create->pointer

### mmap ###
见设计部分


### 关于 `_private_data` ###
在`struct file`和`struct vma`中缺乏
`file_private_data`
`vm_private_data`
这两个成员，主要用于让File和VMA对应到对应的binder在内核中的结构`binder_proc`。

需要添加的是`file`结构中的`void* file_private_data`，至于vma中已经拥有由Yangyang添加的用于mmap2的指向file结构的指针。

> 有待添加`file_private_data`

### 等待队列 ###
这是wait_event_interruptible/wait_up_interruptible

### Workqueue ###
如前所述，是用于一些异步的任务。我没有去问Chenyuheng有没有实现，目前这些异步的任务都是同步实现的，我认为对于正确性没有影响。

### 其他 ###
* 删除 `Proc->tsk->signal->Rlimit`
* 删除关于 FD-array expand 的内容
* seq_file 因为/proc被删所以 useless

vm_operations_struct (closed?)
