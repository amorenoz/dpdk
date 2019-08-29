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
find_internal_resource_by_did(int did)
{
	int found = 0;
	struct internal_list *list;

	pthread_mutex_lock(&internal_list_lock);

	TAILQ_FOREACH(list, &internal_list, next) {
		if (did == list->dev->did) {
			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&internal_list_lock);

	if (!found)
		return NULL;

	return list;
}

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
virtio_vdpa_dma_map_ctrl_queue(struct virtio_vdpa_device *dev, int do_map,
		uint64_t iova)
{
	const struct rte_memzone *mz;
	int ret;

	/*
	 * IOVAs are processes VAs. We cannot use them as the Data and Control
	 * paths are run in different processes, which may (does) lead to
	 * collusions. The trick here is to fixup Ctrl path IOVAs so that they
	 * start after the Data path ranges.
	 */
	if (do_map) {
		mz = dev->cvq->cq.mz;
		ret = rte_vfio_container_dma_map(dev->vfio_container_fd,
				(uint64_t)(uintptr_t)mz->addr,
				iova, mz->len);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to map ctrl ring (%d)", ret);
			return ret;
		}

		dev->cvq->vq_ring_mem = iova;
		iova += mz->len;

		mz = dev->cvq->cq.virtio_net_hdr_mz;
		ret = rte_vfio_container_dma_map(dev->vfio_container_fd,
				(uint64_t)(uintptr_t)mz->addr,
				iova, mz->len);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to map ctrl headers (%d)", ret);
			return ret;
		}

		dev->cvq->cq.virtio_net_hdr_mem = iova;
	} else {
		mz = dev->cvq->cq.mz;
		ret = rte_vfio_container_dma_unmap(dev->vfio_container_fd,
				(uint64_t)(uintptr_t)mz->addr,
				iova, mz->len);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to unmap ctrl ring (%d)", ret);
			return ret;
		}

		dev->cvq->vq_ring_mem = 0;
		iova += mz->len;

		mz = dev->cvq->cq.virtio_net_hdr_mz;
		ret = rte_vfio_container_dma_unmap(dev->vfio_container_fd,
				(uint64_t)(uintptr_t)mz->addr,
				iova, mz->len);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to unmap ctrl headers (%d)", ret);
			return ret;
		}

		dev->cvq->cq.virtio_net_hdr_mem = 0;
	}

	return 0;
}

static int
virtio_vdpa_dma_map(struct virtio_vdpa_device *dev, int do_map)
{
	uint32_t i;
	int ret;
	struct rte_vhost_memory *mem = NULL;
	int vfio_container_fd;
	uint64_t avail_iova = 0;

	ret = rte_vhost_get_mem_table(dev->vid, &mem);
	if (ret < 0 || !mem) {
		DRV_LOG(ERR, "failed to get VM memory layout.");
		return ret;
	}

	vfio_container_fd = dev->vfio_container_fd;

	for (i = 0; i < mem->nregions; i++) {
		struct rte_vhost_mem_region *reg;

		reg = &mem->regions[i];
		DRV_LOG(INFO, "%s, region %u: HVA 0x%" PRIx64 ", "
			"GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".",
			do_map ? "DMA map" : "DMA unmap", i,
			reg->host_user_addr, reg->guest_phys_addr, reg->size);

		if (reg->guest_phys_addr + reg->size > avail_iova)
			avail_iova = reg->guest_phys_addr + reg->size;

		if (do_map) {
			ret = rte_vfio_container_dma_map(vfio_container_fd,
				reg->host_user_addr, reg->guest_phys_addr,
				reg->size);
			if (ret < 0) {
				DRV_LOG(ERR, "DMA map failed.");
				goto exit;
			}
		} else {
			ret = rte_vfio_container_dma_unmap(vfio_container_fd,
				reg->host_user_addr, reg->guest_phys_addr,
				reg->size);
			if (ret < 0) {
				DRV_LOG(ERR, "DMA unmap failed.");
				goto exit;
			}
		}
	}

	if (dev->cvq)
		ret = virtio_vdpa_dma_map_ctrl_queue(dev, do_map, avail_iova);

exit:
	free(mem);

	return ret;
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

static int
virtio_vdpa_get_queue_num(int did, uint32_t *queue_num)
{
	struct internal_list *list;
	struct virtio_vdpa_device *dev;

	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	dev = list->dev;

	*queue_num = dev->max_queue_pairs;

	return 0;
}

static int
virtio_vdpa_get_features(int did, uint64_t *features)
{
	struct internal_list *list;
	struct virtio_vdpa_device *dev;

	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	dev = list->dev;

	*features = VTPCI_OPS(&dev->hw)->get_features(&dev->hw);

	if (!(*features & (1ULL << VIRTIO_F_IOMMU_PLATFORM))) {
		DRV_LOG(ERR, "Device does not support IOMMU");
		return -1;
	}

	if (*features & (1ULL << VIRTIO_NET_F_CTRL_VQ))
		dev->has_ctrl_vq = true;
	else
		dev->has_ctrl_vq = false;

	*features |= (1ULL << VHOST_USER_F_PROTOCOL_FEATURES);

	return 0;
}

#define VDPA_SUPPORTED_PROTOCOL_FEATURES \
		(1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK | \
		 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ | \
		 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD | \
		 1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER)
static int
virtio_vdpa_get_protocol_features(int did __rte_unused, uint64_t *features)
{
	*features = VDPA_SUPPORTED_PROTOCOL_FEATURES;
	return 0;
}

static uint64_t
hva_to_gpa(int vid, uint64_t hva)
{
	struct rte_vhost_memory *mem = NULL;
	struct rte_vhost_mem_region *reg;
	uint32_t i;
	uint64_t gpa = 0;

	if (rte_vhost_get_mem_table(vid, &mem) < 0)
		goto exit;

	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];

		if (hva >= reg->host_user_addr &&
				hva < reg->host_user_addr + reg->size) {
			gpa = hva - reg->host_user_addr + reg->guest_phys_addr;
			break;
		}
	}

exit:
	if (mem)
		free(mem);
	return gpa;
}

static int
virtio_vdpa_start(struct virtio_vdpa_device *dev)
{
	struct virtio_hw *hw = &dev->hw;
	int i, vid, nr_vring, ret;
	struct rte_vhost_vring vr;
	struct virtio_pmd_ctrl ctrl;
	int dlen[1];

	vid = dev->vid;
	nr_vring = rte_vhost_get_vring_num(vid);

	if (dev->vqs)
		rte_free(dev->vqs);

	dev->vqs = rte_zmalloc("virtio_vdpa", sizeof(*dev->vqs) * nr_vring, 0);

	for (i = 0; i < nr_vring; i++) {
		struct virtqueue *vq = &dev->vqs[i];

		rte_vhost_get_vhost_vring(vid, i, &vr);

		vq->vq_queue_index = i;
		vq->vq_nentries = vr.size;
		vq->vq_ring_mem = hva_to_gpa(vid, (uint64_t)(uintptr_t)vr.desc);
		if (vq->vq_ring_mem  == 0) {
			DRV_LOG(ERR, "Fail to get GPA for descriptor ring.");
			ret = -1;
			goto out_free_vqs;
		}

		ret = VTPCI_OPS(hw)->setup_queue(hw, vq);
		if (ret) {
			DRV_LOG(ERR, "Fail to setup queue.");
			goto out_free_vqs;
		}
	}

	if (dev->cvq) {
		ret = VTPCI_OPS(hw)->setup_queue(hw, dev->cvq);
		if (ret) {
			DRV_LOG(ERR, "Fail to setup ctrl queue.");
			goto out_free_vqs;
		}
	}

	vtpci_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER_OK);

	if (!dev->cvq)
		return 0;

	ctrl.hdr.class = VIRTIO_NET_CTRL_MQ;
	ctrl.hdr.cmd = VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
	memcpy(ctrl.data, &dev->max_queue_pairs, sizeof(uint16_t));

	dlen[0] = sizeof(uint16_t);

	ret = virtio_send_command(hw->cvq, &ctrl, dlen, 1);
	if (ret) {
		DRV_LOG(ERR, "Multiqueue configured but send command "
			  "failed, this is too late now...");
		ret = -EINVAL;
		goto out_free_vqs;
	}

	return 0;
out_free_vqs:
	rte_free(dev->vqs);

	return ret;
}

static void
virtio_vdpa_stop(struct virtio_vdpa_device *dev)
{
	struct virtio_hw *hw = &dev->hw;
	uint32_t i, nr_vring;
	int vid = dev->vid;
	struct rte_vhost_vring vr;
	uint16_t last_used_idx, last_avail_idx;

	nr_vring = rte_vhost_get_vring_num(vid);

	vtpci_reset(hw);

	for (i = 0; i < nr_vring; i++) {
		rte_vhost_get_vhost_vring(vid, i, &vr);

		last_used_idx = vr.used->idx;
		last_avail_idx = vr.avail->idx;

		rte_vhost_set_vring_base(vid, i, last_avail_idx,
				last_used_idx);
	}

	rte_free(dev->vqs);
	dev->vqs = NULL;
}

static int
virtio_vdpa_dev_config(int vid)
{
	int did, ret;
	struct internal_list *list;
	struct virtio_vdpa_device *dev;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	dev = list->dev;
	dev->vid = vid;

	rte_spinlock_lock(&dev->lock);

	ret = virtio_vdpa_dma_map(dev, 1);
	if (ret)
		goto out_unlock;

	ret = virtio_vdpa_start(dev);

	if (rte_vhost_host_notifier_ctrl(vid, true) != 0)
		DRV_LOG(NOTICE, "vDPA (%d): software relay is used.", did);

out_unlock:
	rte_spinlock_unlock(&dev->lock);

	return ret;
}

static int
virtio_vdpa_dev_close(int vid)
{
	int did;
	struct internal_list *list;
	struct virtio_vdpa_device *dev;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	dev = list->dev;

	rte_spinlock_lock(&dev->lock);
	virtio_vdpa_stop(dev);
	virtio_vdpa_dma_map(dev, 0);
	rte_spinlock_unlock(&dev->lock);

	return 0;
}


static void
virtio_vdpa_free_ctrl_vq(struct virtio_vdpa_device *dev)
{
	if (!dev->cvq)
		return;

	rte_memzone_free(dev->cvq->cq.virtio_net_hdr_mz);
	rte_memzone_free(dev->cvq->cq.mz);
	rte_free(dev->cvq);

	dev->hw.cvq = NULL;
}

static int
virtio_vdpa_allocate_ctrl_vq(struct virtio_vdpa_device *dev)
{
	struct virtio_hw *hw = &dev->hw;
	char vq_name[VIRTQUEUE_MAX_NAME_SZ];
	char vq_hdr_name[VIRTQUEUE_MAX_NAME_SZ];
	int numa_node = dev->pdev->device.numa_node;
	const struct rte_memzone *mz = NULL, *hdr_mz = NULL;
	uint16_t ctrl_queue_idx = dev->max_queue_pairs * 2;
	uint16_t ctrl_queue_sz;
	int size, ret;

	if (dev->cvq)
		virtio_vdpa_free_ctrl_vq(dev);

	ctrl_queue_sz = VTPCI_OPS(hw)->get_queue_num(hw, ctrl_queue_idx);
	if (ctrl_queue_sz == 0) {
		DRV_LOG(ERR, "Ctrl VQ does not exist");
		return -EINVAL;
	}

	dev->cvq = rte_zmalloc_socket(vq_name, sizeof(*dev->cvq),
			RTE_CACHE_LINE_SIZE, numa_node);
	if (!dev->cvq)
		return -ENOMEM;

	dev->cvq->hw = &dev->hw;
	dev->cvq->vq_queue_index = ctrl_queue_idx;
	dev->cvq->vq_nentries = ctrl_queue_sz;

	if (vtpci_packed_queue(hw)) {
		dev->cvq->vq_packed.used_wrap_counter = 1;
		dev->cvq->vq_packed.cached_flags = VRING_PACKED_DESC_F_AVAIL;
		dev->cvq->vq_packed.event_flags_shadow = 0;
	}

	size = vring_size(hw, ctrl_queue_sz, VIRTIO_PCI_VRING_ALIGN);
	dev->cvq->vq_ring_size = RTE_ALIGN_CEIL(size, VIRTIO_PCI_VRING_ALIGN);

	snprintf(vq_name, sizeof(vq_name), "vdpa_ctrlvq%d",
		 dev->did);

	mz = rte_memzone_reserve_aligned(vq_name, dev->cvq->vq_ring_size,
			numa_node, RTE_MEMZONE_IOVA_CONTIG,
			VIRTIO_PCI_VRING_ALIGN);
	if (mz == NULL) {
		if (rte_errno == EEXIST)
			mz = rte_memzone_lookup(vq_name);
		if (mz == NULL) {
			ret = -ENOMEM;
			goto out_free_cvq;
		}
	}

	memset(mz->addr, 0, mz->len);
	dev->cvq->vq_ring_virt_mem = mz->addr;

	virtio_init_vring(dev->cvq);

	snprintf(vq_hdr_name, sizeof(vq_hdr_name), "vdpa_ctrlvq%d_hdr",
		 dev->did);

	hdr_mz = rte_memzone_reserve_aligned(vq_hdr_name, PAGE_SIZE * 2,
			numa_node, RTE_MEMZONE_IOVA_CONTIG,
			VIRTIO_PCI_VRING_ALIGN);
	if (hdr_mz == NULL) {
		if (rte_errno == EEXIST)
			hdr_mz = rte_memzone_lookup(vq_hdr_name);
		if (hdr_mz == NULL) {
			ret = -ENOMEM;
			goto out_free_mz;
		}
	}

	memset(hdr_mz->addr, 0, hdr_mz->len);

	dev->cvq->cq.vq = dev->cvq;
	dev->cvq->cq.mz = mz;
	dev->cvq->cq.virtio_net_hdr_mz = hdr_mz;
	dev->hw.cvq = &dev->cvq->cq;

	return 0;

out_free_mz:
	rte_memzone_free(mz);
out_free_cvq:
	rte_free(dev->cvq);
	dev->cvq = NULL;

	return ret;
}

static int
virtio_vdpa_set_features(int vid)
{
	uint64_t features;
	int did, ret;
	struct internal_list *list;
	struct virtio_vdpa_device *dev;
	struct virtio_hw *hw;

	did = rte_vhost_get_vdpa_device_id(vid);
	list = find_internal_resource_by_did(did);
	if (list == NULL) {
		DRV_LOG(ERR, "Invalid device id: %d", did);
		return -1;
	}

	dev = list->dev;
	hw = &dev->hw;
	rte_vhost_get_negotiated_features(vid, &features);

	features |= (1ULL << VIRTIO_F_IOMMU_PLATFORM);
	if (dev->has_ctrl_vq)
		features |= (1ULL << VIRTIO_NET_F_CTRL_VQ);

	VTPCI_OPS(&dev->hw)->set_features(&dev->hw, features);
	hw->guest_features = features;

	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_VQ)) {
		if (vtpci_with_feature(hw, VIRTIO_NET_F_MQ)) {
			vtpci_read_dev_config(hw,
				offsetof(struct virtio_net_config,
					max_virtqueue_pairs),
				&dev->max_queue_pairs,
				sizeof(dev->max_queue_pairs));
		} else {
			dev->max_queue_pairs = 1;
		}

		ret = virtio_vdpa_allocate_ctrl_vq(dev);
		if (ret) {
			DRV_LOG(ERR, "Failed to allocate ctrl vq");
			return ret;
		}
	}

	return 0;
}

static struct rte_vdpa_dev_ops virtio_vdpa_ops = {
	.get_queue_num = virtio_vdpa_get_queue_num,
	.get_features = virtio_vdpa_get_features,
	.get_protocol_features = virtio_vdpa_get_protocol_features,
	.dev_conf = virtio_vdpa_dev_config,
	.dev_close = virtio_vdpa_dev_close,
	.set_features = virtio_vdpa_set_features,
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

