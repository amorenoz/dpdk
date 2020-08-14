/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_EMUDEV_H_
#define _RTE_EMUDEV_H_

#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_ring.h>

typedef void *rte_emudev_conf_t;
typedef void *rte_emudev_attr_t;
typedef void *rte_emudev_mem_table_t;
typedef char *emu_dev_type_t;

struct rte_emu_dev;

struct emu_dev_info {
	emu_dev_type_t dev_type;
	uint32_t max_qp_num;
	uint32_t max_event_num;
};

struct emu_dev_q_info {
	uint64_t base;
	uint64_t size;
	uint32_t doorbell_id;
	uint32_t irq_vector;
	void *priv;
};

struct emu_dev_irq_info {
	uint32_t vector;
	int fd;
	void *priv;
};

struct emu_dev_db_info {
	uint32_t id;
	uint32_t flag;
#define EMU_DEV_DB_FD	(0x1 << 0)
#define EMU_DEV_DB_MEM	(0x1 << 1)
	union {
		int fd;
		struct {
			uint64_t base;
			uint64_t size;
		} mem;
	} data;
	void *priv;
};

/**
 * Back-end driver and emualated device provider should have
 * the same definiton of events and events message.
 */
struct emu_dev_event_channel {
	int fd;
	struct rte_ring *queue;
};

struct emu_dev_attr_info {
	const char *attr_name;
	rte_emudev_attr_t attr;
};

struct emu_dev_ops {
	int (*dev_start)(struct rte_emu_dev *dev);
	void (*dev_stop)(struct rte_emu_dev *dev);
	int (*dev_configure)(struct rte_emu_dev *dev,
		rte_emudev_conf_t dev_conf);
	int (*dev_close)(struct rte_emu_dev *dev);
	struct emu_dev_info *(*get_dev_info)(struct rte_emu_dev *dev);
	int (*subscribe_event)(struct rte_emu_dev *dev,
		const struct emu_dev_event_channel *ev_chnl);
	int (*unsubscribe_event)(struct rte_emu_dev *dev,
		const struct emu_dev_event_channel *ev_chnl);
	rte_emudev_mem_table_t (*get_mem_table)(struct rte_emu_dev *dev);
	struct emu_dev_q_info *(*get_queue_info)(struct rte_emu_dev *dev,
		uint32_t queue);
	struct emu_dev_irq_info *(*get_irq_info)(struct rte_emu_dev *dev,
		uint32_t vector);
	struct emu_dev_db_info *(*get_db_info)(struct rte_emu_dev *dev,
		uint32_t doorbell);
	rte_emudev_attr_t (*get_attr)(struct rte_emu_dev *dev,
		const char *attr_name);
	int (*set_attr)(struct rte_emu_dev *dev, const char *attr_name,
		rte_emudev_attr_t attr);
	int (*region_map)(struct rte_emu_dev *dev, const char *region_name,
		uint16_t region_size, uint64_t *base_addr);
};

struct rte_emu_dev {
	struct rte_device *device;
	const struct emu_dev_ops *dev_ops;
	const struct emu_dev_event_channel *ev_chnl;
	struct emu_dev_info *dev_info;
	uint16_t num_attr;
	struct emu_dev_attr_info **attr;
	void *priv_data;
} __rte_cache_aligned;

/**
 * Note that 'rte_emu_dev_allocate','rte_emu_dev_release' and
 * 'rte_emu_dev_allocated' should be called by emulated device
 * provider.
 * /

/**
 * Allocate a new emudev for an emulation device and retures the pointer
 * to the emudev.
 *
 * @param name
 *  Name of the emudev
 * @return
 *  Pointer to rte_emu_dev on success, NULL on failure
 */
struct rte_emu_dev *
rte_emu_dev_allocate(const char *name);

/**
 * Release the emudev.
 *
 * @param dev
 *  The emulated device
 * @return
 *  0 on success, -1 on failure
 */
int
rte_emu_dev_release(struct rte_emu_dev *dev);

/**
 * Find an emudev using name.
 *
 * @param name
 *  Name of the emudev
 * @return
 *  Pointer to rte_emu_dev on success, NULL on failure
 */
struct rte_emu_dev *
rte_emu_dev_allocated(const char *name);

/**
 * Start an emulation device.
 *
 * @param dev_id
 *  Device ID of emudev
 * @return
 *  0 on success, -1 on failure
 */
int rte_emu_dev_start(uint16_t dev_id);

/**
 * Stop an emulation device.
 *
 * @param dev_id
 *  Device ID of emudev
 */
void rte_emu_dev_stop(uint16_t dev_id);

/**
 * Configure an emulation device.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param dev_conf
 *  Device configure info
 * @return
 *  0 on success, -1 on failure
 */
int rte_emu_dev_configure(uint16_t dev_id, rte_emudev_conf_t dev_conf);

/**
 * Close an emulation device.
 *
 * @param dev_id
 *  Device ID of emudev
 */
void rte_emu_dev_close(uint16_t dev_id);

/* Note that below APIs should only be called by back-end driver */

/**
 * Back-end driver subscribes events of the emulated device.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param ev_chnl
 *  Event channel that events should be passed to
 * @return
 *  0 on success, -1 on failure
 */
int rte_emu_subscribe_event(uint16_t dev_id,
		const struct emu_dev_event_channel *ev_chnl);

/**
 * Back-end driver unsubscribes events of the emulated device.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param set
 *  Event channel that events should be passed to
 * @return
 *  0 on success, -1 on failure
 */
int rte_emu_unsubscribe_event(uint16_t dev_id,
		const struct emu_dev_event_channel *ev_chnl);

/**
 * Back-end driver gets the device info of the emulated device.
 *
 * @param dev_id
 *  Device ID of emudev
 * @return
 *  Pointer to dev info on success, NULL on failure
 */
struct emu_dev_info *rte_emu_get_dev_info(uint16_t dev_id);

/**
 * Get the memory table content and operations of the emulated device.
 *
 * @param dev_id
 *  Device ID of emudev
 * @return
 *  Pointer to memory table on success, NULL on failure
 */
rte_emudev_mem_table_t rte_emu_get_mem_table(uint16_t dev_id);

/**
 * Get queue info of the emudev.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param queue
 *  Queue ID of emudev
 * @return
 *  Pointer to queue info on success, NULL on failure
 */
struct emu_dev_q_info *rte_emu_get_queue_info(uint16_t dev_id,
		uint32_t queue);

/**
 * Get irq info of the emudev.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param vector
 *  Interrupt vector
 * @return
 *  Pointer to irq info on success, NULL on failure
 */
struct emu_dev_irq_info *rte_emu_get_irq_info(uint16_t dev_id,
		uint32_t vector);

/**
 * Get doorbell info of the emudev.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param doorbell
 *  Doorbell ID
 * @return
 *  Pointer to doorbell info on success, NULL on failure
 */
struct emu_dev_db_info *rte_emu_get_db_info(uint16_t dev_id,
		uint32_t doorbell);

/**
 * Set attribute of the emudev.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param attr_name
 *  Opaque object representing an attribute in implementation.
 * @param attr
 *  Pointer to attribute
 * @return
 *  0 on success, -1 on failure
 */
int rte_emu_set_attr(uint16_t dev_id, const char *attr_name,
	rte_emudev_attr_t attr);

/**
 * Get attribute of the emudev.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param attr_name
 *  Opaque object representing an attribute in implementation.
 * @return
 *  Corresponding attr on success, NULL on failure
 */
rte_emudev_attr_t rte_emu_get_attr(uint16_t dev_id, const char *attr_name);

/**
 * Back-end driver maps a region to the emulated device.
 * Region name identifies the meaning of the region and the emulated
 * device and the back-end driver should have the same definition of
 * region name and its meaning.
 *
 * @param dev_id
 *  Device ID of emudev
 * @param region_name
 *  .
 * @param attr
 *  Pointer to attribute
 * @return
 *  0 on success, -1 on failure
 */
int rte_emu_region_map(uint16_t dev_id, const char *region_name,
	uint16_t region_size, uint64_t *base_addr);

extern struct rte_emu_dev rte_emu_devices[];
#endif /* _RTE_EMUDEV_H_ */
