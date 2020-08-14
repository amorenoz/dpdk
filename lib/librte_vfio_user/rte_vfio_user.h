/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _VFIO_USER_H
#define _VFIO_USER_H

#include <stdint.h>
#include <stddef.h>
#include <linux/vfio.h>
#include <net/if.h>
#include <sys/queue.h>
#include <sys/un.h>

#define VFIO_USER_MSG_MAX_NREGIONS 8
#define VFIO_USER_MAX_MEM_REGIONS 256
#define VFIO_MAX_RW_DATA 256
#define VFIO_USER_MAX_FD 64
#define VFIO_USER_IRQ_MAX_DATA 64
#define VFIO_USER_MAX_IRQ_FD 64

typedef enum VFIO_USER_CMD_TYPE {
	VFIO_USER_NONE = 0,
	VFIO_USER_VERSION = 1,
	VFIO_USER_DMA_MAP = 2,
	VFIO_USER_DMA_UNMAP = 3,
	VFIO_USER_DEVICE_GET_INFO = 4,
	VFIO_USER_DEVICE_GET_REGION_INFO = 5,
	VFIO_USER_DEVICE_GET_IRQ_INFO = 6,
	VFIO_USER_DEVICE_SET_IRQS = 7,
	VFIO_USER_REGION_READ = 8,
	VFIO_USER_REGION_WRITE = 9,
	VFIO_USER_DMA_READ = 10,
	VFIO_USER_DMA_WRITE = 11,
	VFIO_USER_VM_INTERRUPT = 12,
	VFIO_USER_DEVICE_RESET = 13,
	VFIO_USER_MAX = 14,
} VFIO_USER_CMD_TYPE;

struct vfio_user_mem_reg {
	uint64_t gpa;
	uint64_t size;
	uint64_t fd_offset;
	uint32_t protection;	/* attributes in <sys/mman.h> */
#define VFIO_USER_MEM_MAPPABLE	(0x1 << 0)
	uint32_t flags;
};

struct vfio_user_dev_info {
	uint32_t argsz;		/* Reserved in vfio-user */
	uint32_t flags;
	uint32_t num_regions;
	uint32_t num_irqs;
};

struct vfio_user_reg_rw {
	uint64_t reg_offset;
	uint32_t reg_idx;
	uint32_t size;
	char data[VFIO_MAX_RW_DATA];
};

struct vfio_user_dma_rw {
	uint64_t addr;
	uint32_t size;
	char data[VFIO_MAX_RW_DATA];
};

struct vfio_user_intr {
	uint32_t type;
	uint32_t vector;
};

typedef struct vfio_user_msg {
	uint16_t dev_id;
	uint16_t msg_id;
	uint32_t cmd;
	uint32_t size;
#define VFIO_USER_REPLY_MASK	(0x1 << 0)
#define VFIO_USER_NEED_NO_RP	(0x1 << 1)
	uint32_t flags;
	union {
		struct vfio_user_mem_reg memory[VFIO_USER_MSG_MAX_NREGIONS];
		struct vfio_user_dev_info dev_info;
		struct vfio_region_info reg_info;
		struct vfio_irq_info irq_info;
		struct vfio_irq_set irq_set;
		struct vfio_user_reg_rw reg_rw;
		struct vfio_user_dma_rw dma_rw;
		struct vfio_user_intr intr;
	} payload;
	int fds[VFIO_USER_MAX_FD];
	int fd_num;
} __attribute((packed)) VFIO_USER_MSG;

#define VFIO_USER_MSG_HDR_SIZE offsetof(VFIO_USER_MSG, payload.dev_info)

enum vfio_user_msg_handle_result {
	VFIO_USER_MSG_HANDLE_ERR = -1,
	VFIO_USER_MSG_HANDLE_OK = 0,
	VFIO_USER_MSG_HANDLE_REPLY = 1,
};

struct vfio_user_mem_table_entry {
	struct vfio_user_mem_reg region;
	uint64_t host_user_addr;
	void	 *mmap_addr;
	uint64_t mmap_size;
	int fd;
};

struct vfio_user_mem {
	uint32_t entry_num;
	struct vfio_user_mem_table_entry entry[VFIO_USER_MAX_MEM_REGIONS];
};

struct vfio_user_regions {
	uint32_t reg_num;
	struct vfio_region_info **reg_info;
};

struct vfio_user_irq_info {
	uint32_t irq_num;
	struct vfio_irq_info *irq_info;
};

struct vfio_user_irq_set {
	uint32_t set_num;
	struct vfio_irq_set **irq;
	int fds[VFIO_USER_MAX_IRQ_FD];
};

struct vfio_user_irqs {
	struct vfio_user_irq_info *info;
	struct vfio_user_irq_set *set;
};

struct vfio_user_region_resource {
	void *base;
	uint32_t size;
	int fd;
};

struct vfio_user_resource {
	uint16_t resource_num;
	struct vfio_user_region_resource res[];
};

struct vfio_user {
	int dev_id;
	int is_ready;
#define IF_NAME_SZ (IFNAMSIZ > PATH_MAX ? IFNAMSIZ : PATH_MAX)
	char sock_addr[IF_NAME_SZ];
	const struct vfio_user_notify_ops *ops;
	struct vfio_user_mem *mem;
	struct vfio_user_dev_info *dev_info;
	struct vfio_user_regions *reg;
	struct vfio_user_irqs *irq;
	struct vfio_user_resource *res;
};

struct vfio_user_notify_ops {
	int (*new_device)(int dev_id);		/* Add device */
	void (*destroy_device)(int dev_id);	/* Remove device */
	int (*update_status)(int dev_id);	/* Update device status */
};

typedef void (*vfio_user_log)(const char *format, ...);

typedef int (*event_handler)(int fd, void *data);

typedef struct listen_fd_info {
	int fd;
	uint32_t event;
	event_handler ev_handle;
	void *data;
} FD_INFO;

struct vfio_user_epoll {
	int epfd;
	FD_INFO fdinfo[VFIO_USER_MAX_FD];
	uint32_t fd_num;	/* Current num of listen_fd */
	struct epoll_event *events;
	pthread_mutex_t fd_mutex;
};

struct vfio_user_socket {
	char *sock_addr;
	struct sockaddr_un un;
	int sock_fd;
	int dev_id;
};

struct vfio_user_ep_sock {
	struct vfio_user_epoll ep;
	struct vfio_user_socket *sock[VFIO_USER_MAX_FD];
	uint32_t sock_num;
	pthread_mutex_t mutex;
};

/**
 * Register a vfio-user device.
 *
 * @param sock_addr
 *  Unix domain socket address
 * @param ops
 *  Notify ops for the device
 * @param log
 *  Log callback for the device
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_register(const char *sock_addr,
	const struct vfio_user_notify_ops *ops,
	vfio_user_log log);

/**
 * Unregister a vfio-user device.
 *
 * @param sock_addr
 *  Unix domain socket address
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_unregister(const char *sock_addr);

/**
 * Start vfio-user handling for the device.
 *
 * This function triggers vfio-user message handling.
 * @param sock_addr
 *  Unix domain socket address
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_start(const char *sock_addr);

/**
 * Stop vfio-user handling for the device.
 *
 * This function stops vfio-user message handling.
 * @param sock_addr
 *  Unix domain socket address
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_stop(const char *sock_addr);

/**
 * Get the socket address for a vfio-user device.
 *
 * @param dev_id
 *  Vfio-user device ID
 * @param buf
 *  Buffer to store socket address
 * @param len
 *  The len of buf
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_get_sock_addr(int dev_id, char *buf, size_t len);

/**
 * Get the memory table of a vfio-user device.
 *
 * @param dev_id
 *  Vfio-user device ID
 * @return
 *  Pointer to memory table on success, NULL on failure
 */
struct vfio_user_mem *rte_vfio_user_get_mem_table(int dev_id);

/**
 * Get the irq set of a vfio-user device.
 *
 * @param dev_id
 *  Vfio-user device ID
 * @return
 *  Pointer to irq set on success, NULL on failure
 */
struct vfio_user_irq_set *rte_vfio_user_get_irq(int dev_id);

/**
 * Set the device info for a vfio-user device.
 *
 * @param sock_addr
 *  Unix domain socket address
 * @param dev_info
 *  Device info for the vfio-user device
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_set_dev_info(const char *sock_addr,
	struct vfio_user_dev_info *dev_info);

/**
 * Set the region info for a vfio-user device.
 *
 * @param sock_addr
 *  Unix domain socket address
 * @param reg
 *  Region info for the vfio-user device
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_set_reg_info(const char *sock_addr,
	struct vfio_user_regions *reg);

/**
 * Set the irq info for a vfio-user device.
 *
 * @param sock_addr
 *  Unix domain socket address
 * @param irq
 *  IRQ info for the vfio-user device
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_set_irq_info(const char *sock_addr,
	struct vfio_user_irq_info *irq);

/**
 * Set the device resource for a vfio-user device.
 *
 * @param sock_addr
 *  Unix domain socket address
 * @param res
 *  Resource info for the vfio-user device
 * @return
 *  0 on success, -1 on failure
 */
int rte_vfio_user_set_resource(const char *sock_addr,
	struct vfio_user_resource *res);

#endif
