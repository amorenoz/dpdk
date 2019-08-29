/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 * Copyright(c) 2019 Red Hat, Inc.
 */

#include <unistd.h>
#include <sys/ioctl.h>

#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_vdpa.h>
#include <rte_vfio.h>
#include <rte_vhost.h>

#include "virtio_pci.h"
#include "virtqueue.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_vdpa_logtype, \
		"VIRTIO_VDPA %s(): " fmt "\n", __func__, ##args)

#define VIRTIO_VDPA_MODE		"vdpa"

static const char * const virtio_vdpa_valid_arguments[] = {
	VIRTIO_VDPA_MODE,
	NULL
};

static int virtio_vdpa_logtype;

struct virtio_vdpa_device {
	struct rte_vdpa_dev_addr dev_addr;
	struct rte_pci_device *pdev;
	struct virtio_hw hw;
	int vfio_container_fd;
	int vfio_group_fd;
	int vfio_dev_fd;
	int iommu_group_num;
	int vid;
	int did;
	uint16_t max_queue_pairs;
	bool has_ctrl_vq;
	struct virtqueue *vqs;
	struct virtqueue *cvq;
	rte_spinlock_t lock;
};

struct internal_list {
	TAILQ_ENTRY(internal_list) next;
	struct virtio_vdpa_device *dev;
};

TAILQ_HEAD(internal_list_head, internal_list);
static struct internal_list_head internal_list =
	TAILQ_HEAD_INITIALIZER(internal_list);

static pthread_mutex_t internal_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct internal_list *
find_internal_resource_by_dev(struct rte_pci_device *pdev)
{
	int found = 0;
	struct internal_list *list;

	pthread_mutex_lock(&internal_list_lock);

	TAILQ_FOREACH(list, &internal_list, next) {
		if (pdev == list->dev->pdev) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&internal_list_lock);

	if (!found)
		return NULL;

	return list;
}

static int
virtio_vdpa_vfio_setup(struct virtio_vdpa_device *dev)
{
	struct rte_pci_device *pdev = dev->pdev;
	char devname[RTE_DEV_NAME_MAX_LEN] = {0};
	int iommu_group_num;

	dev->vfio_dev_fd = -1;
	dev->vfio_group_fd = -1;
	dev->vfio_container_fd = -1;
	dev->iommu_group_num = -1;

	rte_pci_device_name(&pdev->addr, devname, RTE_DEV_NAME_MAX_LEN);
	rte_vfio_get_group_num(rte_pci_get_sysfs_path(), devname,
			&iommu_group_num);

	dev->vfio_container_fd = rte_vfio_container_create();
	if (dev->vfio_container_fd < 0)
		return -1;

	dev->vfio_group_fd =
		rte_vfio_container_group_bind(dev->vfio_container_fd,
			iommu_group_num);
	if (dev->vfio_group_fd < 0)
		goto err_container_destroy;

	if (rte_pci_map_device(pdev))
		goto err_container_unbind;

	dev->vfio_dev_fd = pdev->intr_handle.vfio_dev_fd;
	dev->iommu_group_num = iommu_group_num;

	return 0;

err_container_unbind:
	rte_vfio_container_group_unbind(dev->vfio_container_fd,
			iommu_group_num);
err_container_destroy:
	rte_vfio_container_destroy(dev->vfio_container_fd);

	dev->vfio_dev_fd = -1;
	dev->vfio_group_fd = -1;
	dev->vfio_container_fd = -1;
	dev->iommu_group_num = -1;

	return -1;
}

static struct rte_vdpa_dev_ops virtio_vdpa_ops = {
};

static inline int
open_int(const char *key __rte_unused, const char *value, void *extra_args)
{
	uint16_t *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (uint16_t)strtoul(value, NULL, 0);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}

static int
virtio_vdpa_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	struct virtio_vdpa_device *dev;
	struct internal_list *list = NULL;
	struct rte_kvargs *kvlist = NULL;
	int ret, vdpa_mode = 0;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (!pci_dev->device.devargs)
		return -1;

	kvlist = rte_kvargs_parse(pci_dev->device.devargs->args,
			virtio_vdpa_valid_arguments);
	if (kvlist == NULL)
		return -1;

	/* probe only when vdpa mode is specified */
	if (rte_kvargs_count(kvlist, VIRTIO_VDPA_MODE) == 0)
		goto err_free_kvargs;

	ret = rte_kvargs_process(kvlist, VIRTIO_VDPA_MODE, &open_int,
			&vdpa_mode);
	if (ret < 0 || vdpa_mode == 0)
		goto err_free_kvargs;

	list = rte_zmalloc("virtio_vdpa", sizeof(*list), 0);
	if (list == NULL)
		goto err_free_kvargs;

	dev = rte_zmalloc("virtio_vdpa", sizeof(*dev), 0);
	if (!dev)
		goto err_free_list;

	dev->pdev = pci_dev;
	rte_spinlock_init(&dev->lock);

	if (virtio_vdpa_vfio_setup(dev) < 0) {
		DRV_LOG(ERR, "failed to setup device %s", pci_dev->name);
		goto err_free_vvdev;
	}

	dev->dev_addr.pci_addr = pci_dev->addr;
	dev->dev_addr.type = PCI_ADDR;
	dev->max_queue_pairs = 1;
	list->dev = dev;

	if (vtpci_init(pci_dev, &dev->hw))
		goto err_free_vfio;

	dev->did = rte_vdpa_register_device(&dev->dev_addr,
				&virtio_vdpa_ops);

	if (dev->did < 0) {
		DRV_LOG(ERR, "failed to register device %s", pci_dev->name);
		goto err_free_vfio;
	}

	pthread_mutex_lock(&internal_list_lock);
	TAILQ_INSERT_TAIL(&internal_list, list, next);
	pthread_mutex_unlock(&internal_list_lock);

	rte_kvargs_free(kvlist);

	return 0;

err_free_vfio:
	rte_vfio_container_destroy(dev->vfio_container_fd);
err_free_vvdev:
	rte_free(dev);
err_free_list:
	rte_free(list);
err_free_kvargs:
	rte_kvargs_free(kvlist);

	return 1;
}

static int
virtio_vdpa_pci_remove(struct rte_pci_device *pci_dev)
{
	struct virtio_vdpa_device *dev;
	struct internal_list *list;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	list = find_internal_resource_by_dev(pci_dev);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device: %s", pci_dev->name);
		return -1;
	}

	dev = list->dev;

	rte_vdpa_unregister_device(dev->did);
	rte_pci_unmap_device(dev->pdev);
	rte_vfio_container_group_unbind(dev->vfio_container_fd,
			dev->iommu_group_num);
	rte_vfio_container_destroy(dev->vfio_container_fd);

	pthread_mutex_lock(&internal_list_lock);
	TAILQ_REMOVE(&internal_list, list, next);
	pthread_mutex_unlock(&internal_list_lock);

	rte_free(dev->vqs);
	rte_free(list);
	rte_free(dev);

	return 0;
}

static const struct rte_pci_id pci_id_virtio_vdpa_map[] = {
	{ .class_id = RTE_CLASS_ANY_ID,
	  .vendor_id = VIRTIO_PCI_VENDORID,
	  .device_id = VIRTIO_PCI_LEGACY_DEVICEID_NET,
	  .subsystem_vendor_id = VIRTIO_PCI_VENDORID,
	  .subsystem_device_id = VIRTIO_PCI_SUBSY_DEVICEID_NET,
	},
	{ .class_id = RTE_CLASS_ANY_ID,
	  .vendor_id = VIRTIO_PCI_VENDORID,
	  .device_id = VIRTIO_PCI_MODERN_DEVICEID_NET,
	  .subsystem_vendor_id = VIRTIO_PCI_VENDORID,
	  .subsystem_device_id = VIRTIO_PCI_SUBSY_DEVICEID_NET,
	},
	{ .vendor_id = 0, /* sentinel */
	},
};

static struct rte_pci_driver rte_virtio_vdpa = {
	.id_table = pci_id_virtio_vdpa_map,
	.drv_flags = 0,
	.probe = virtio_vdpa_pci_probe,
	.remove = virtio_vdpa_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_virtio_vdpa, rte_virtio_vdpa);
RTE_PMD_REGISTER_PCI_TABLE(net_virtio_vdpa, pci_id_virtio_vdpa_map);
RTE_PMD_REGISTER_KMOD_DEP(net_virtio_vdpa, "* vfio-pci");

RTE_INIT(virtio_vdpa_init_log)
{
	virtio_vdpa_logtype = rte_log_register("pmd.net.virtio_vdpa");
	if (virtio_vdpa_logtype >= 0)
		rte_log_set_level(virtio_vdpa_logtype, RTE_LOG_NOTICE);
}

