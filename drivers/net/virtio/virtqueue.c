/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#include <stdint.h>
#include <unistd.h>

#include <rte_mbuf.h>

#include "virtqueue.h"
#include "virtio_logs.h"
#include "virtio_pci.h"
#include "virtio_rxtx_simple.h"

/*
 * Two types of mbuf to be cleaned:
 * 1) mbuf that has been consumed by backend but not used by virtio.
 * 2) mbuf that hasn't been consued by backend.
 */
struct rte_mbuf *
virtqueue_detach_unused(struct virtqueue *vq)
{
	struct rte_mbuf *cookie;
	struct virtio_hw *hw;
	uint16_t start, end;
	int type, idx;

	if (vq == NULL)
		return NULL;

	hw = vq->hw;
	type = virtio_get_queue_type(hw, vq->vq_queue_index);
	start = vq->vq_avail_idx & (vq->vq_nentries - 1);
	end = (vq->vq_avail_idx + vq->vq_free_cnt) & (vq->vq_nentries - 1);

	for (idx = 0; idx < vq->vq_nentries; idx++) {
		if (hw->use_simple_rx && type == VTNET_RQ) {
			if (start <= end && idx >= start && idx < end)
				continue;
			if (start > end && (idx >= start || idx < end))
				continue;
			cookie = vq->sw_ring[idx];
			if (cookie != NULL) {
				vq->sw_ring[idx] = NULL;
				return cookie;
			}
		} else {
			cookie = vq->vq_descx[idx].cookie;
			if (cookie != NULL) {
				vq->vq_descx[idx].cookie = NULL;
				return cookie;
			}
		}
	}

	return NULL;
}

/* Flush used descs */
static void
virtqueue_rxvq_flush_packed(struct virtqueue *vq)
{
	struct vq_desc_extra *dxp;
	uint16_t i;

	struct vring_packed_desc *descs = vq->vq_packed.ring.desc;
	int cnt = 0;

	i = vq->vq_used_cons_idx;
	while (desc_is_used(&descs[i], vq) && cnt++ < vq->vq_nentries) {
		dxp = &vq->vq_descx[descs[i].id];
		if (dxp->cookie != NULL) {
			rte_pktmbuf_free(dxp->cookie);
			dxp->cookie = NULL;
		}
		vq->vq_free_cnt++;
		vq->vq_used_cons_idx++;
		if (vq->vq_used_cons_idx >= vq->vq_nentries) {
			vq->vq_used_cons_idx -= vq->vq_nentries;
			vq->vq_packed.used_wrap_counter ^= 1;
		}
		i = vq->vq_used_cons_idx;
	}
}

/* Flush the elements in the used ring. */
static void
virtqueue_rxvq_flush_split(struct virtqueue *vq)
{
	struct virtnet_rx *rxq = &vq->rxq;
	struct virtio_hw *hw = vq->hw;
	struct vring_used_elem *uep;
	struct vq_desc_extra *dxp;
	uint16_t used_idx, desc_idx;
	uint16_t nb_used, i;

	nb_used = VIRTQUEUE_NUSED(vq);

	for (i = 0; i < nb_used; i++) {
		used_idx = vq->vq_used_cons_idx & (vq->vq_nentries - 1);
		uep = &vq->vq_split.ring.used->ring[used_idx];
		if (hw->use_simple_rx) {
			desc_idx = used_idx;
			rte_pktmbuf_free(vq->sw_ring[desc_idx]);
			vq->vq_free_cnt++;
		} else if (hw->use_inorder_rx) {
			desc_idx = (uint16_t)uep->id;
			dxp = &vq->vq_descx[desc_idx];
			if (dxp->cookie != NULL) {
				rte_pktmbuf_free(dxp->cookie);
				dxp->cookie = NULL;
			}
			vq_ring_free_inorder(vq, desc_idx, 1);
		} else {
			desc_idx = (uint16_t)uep->id;
			dxp = &vq->vq_descx[desc_idx];
			if (dxp->cookie != NULL) {
				rte_pktmbuf_free(dxp->cookie);
				dxp->cookie = NULL;
			}
			vq_ring_free_chain(vq, desc_idx);
		}
		vq->vq_used_cons_idx++;
	}

	if (hw->use_simple_rx) {
		while (vq->vq_free_cnt >= RTE_VIRTIO_VPMD_RX_REARM_THRESH) {
			virtio_rxq_rearm_vec(rxq);
			if (virtqueue_kick_prepare(vq))
				virtqueue_notify(vq);
		}
	}
}

/* Flush the elements in the used ring. */
void
virtqueue_rxvq_flush(struct virtqueue *vq)
{
	struct virtio_hw *hw = vq->hw;

	if (vtpci_packed_queue(hw))
		virtqueue_rxvq_flush_packed(vq);
	else
		virtqueue_rxvq_flush_split(vq);
}

static struct virtio_pmd_ctrl *
virtio_send_command_packed(struct virtnet_ctl *cvq,
			   struct virtio_pmd_ctrl *ctrl,
			   int *dlen, int pkt_num)
{
	struct virtqueue *vq = cvq->vq;
	int head;
	struct vring_packed_desc *desc = vq->vq_packed.ring.desc;
	struct virtio_pmd_ctrl *result;
	uint16_t flags;
	int sum = 0;
	int nb_descs = 0;
	int k;

	/*
	 * Format is enforced in qemu code:
	 * One TX packet for header;
	 * At least one TX packet per argument;
	 * One RX packet for ACK.
	 */
	head = vq->vq_avail_idx;
	flags = vq->vq_packed.cached_flags;
	desc[head].addr = cvq->virtio_net_hdr_mem;
	desc[head].len = sizeof(struct virtio_net_ctrl_hdr);
	vq->vq_free_cnt--;
	nb_descs++;
	if (++vq->vq_avail_idx >= vq->vq_nentries) {
		vq->vq_avail_idx -= vq->vq_nentries;
		vq->vq_packed.cached_flags ^= VRING_PACKED_DESC_F_AVAIL_USED;
	}

	for (k = 0; k < pkt_num; k++) {
		desc[vq->vq_avail_idx].addr = cvq->virtio_net_hdr_mem
			+ sizeof(struct virtio_net_ctrl_hdr)
			+ sizeof(ctrl->status) + sizeof(uint8_t) * sum;
		desc[vq->vq_avail_idx].len = dlen[k];
		desc[vq->vq_avail_idx].flags = VRING_DESC_F_NEXT |
			vq->vq_packed.cached_flags;
		sum += dlen[k];
		vq->vq_free_cnt--;
		nb_descs++;
		if (++vq->vq_avail_idx >= vq->vq_nentries) {
			vq->vq_avail_idx -= vq->vq_nentries;
			vq->vq_packed.cached_flags ^=
				VRING_PACKED_DESC_F_AVAIL_USED;
		}
	}

	desc[vq->vq_avail_idx].addr = cvq->virtio_net_hdr_mem
		+ sizeof(struct virtio_net_ctrl_hdr);
	desc[vq->vq_avail_idx].len = sizeof(ctrl->status);
	desc[vq->vq_avail_idx].flags = VRING_DESC_F_WRITE |
		vq->vq_packed.cached_flags;
	vq->vq_free_cnt--;
	nb_descs++;
	if (++vq->vq_avail_idx >= vq->vq_nentries) {
		vq->vq_avail_idx -= vq->vq_nentries;
		vq->vq_packed.cached_flags ^= VRING_PACKED_DESC_F_AVAIL_USED;
	}

	virtio_wmb(vq->hw->weak_barriers);
	desc[head].flags = VRING_DESC_F_NEXT | flags;

	virtio_wmb(vq->hw->weak_barriers);
	virtqueue_notify(vq);

	/* wait for used descriptors in virtqueue */
	while (!desc_is_used(&desc[head], vq))
		usleep(100);

	virtio_rmb(vq->hw->weak_barriers);

	/* now get used descriptors */
	vq->vq_free_cnt += nb_descs;
	vq->vq_used_cons_idx += nb_descs;
	if (vq->vq_used_cons_idx >= vq->vq_nentries) {
		vq->vq_used_cons_idx -= vq->vq_nentries;
		vq->vq_packed.used_wrap_counter ^= 1;
	}

	PMD_INIT_LOG(DEBUG, "vq->vq_free_cnt=%d\n"
			"vq->vq_avail_idx=%d\n"
			"vq->vq_used_cons_idx=%d\n"
			"vq->vq_packed.cached_flags=0x%x\n"
			"vq->vq_packed.used_wrap_counter=%d\n",
			vq->vq_free_cnt,
			vq->vq_avail_idx,
			vq->vq_used_cons_idx,
			vq->vq_packed.cached_flags,
			vq->vq_packed.used_wrap_counter);

	result = cvq->virtio_net_hdr_mz->addr;
	return result;
}

static struct virtio_pmd_ctrl *
virtio_send_command_split(struct virtnet_ctl *cvq,
			  struct virtio_pmd_ctrl *ctrl,
			  int *dlen, int pkt_num)
{
	struct virtio_pmd_ctrl *result;
	struct virtqueue *vq = cvq->vq;
	uint32_t head, i;
	int k, sum = 0;

	head = vq->vq_desc_head_idx;

	/*
	 * Format is enforced in qemu code:
	 * One TX packet for header;
	 * At least one TX packet per argument;
	 * One RX packet for ACK.
	 */
	vq->vq_split.ring.desc[head].flags = VRING_DESC_F_NEXT;
	vq->vq_split.ring.desc[head].addr = cvq->virtio_net_hdr_mem;
	vq->vq_split.ring.desc[head].len = sizeof(struct virtio_net_ctrl_hdr);
	vq->vq_free_cnt--;
	i = vq->vq_split.ring.desc[head].next;

	for (k = 0; k < pkt_num; k++) {
		vq->vq_split.ring.desc[i].flags = VRING_DESC_F_NEXT;
		vq->vq_split.ring.desc[i].addr = cvq->virtio_net_hdr_mem
			+ sizeof(struct virtio_net_ctrl_hdr)
			+ sizeof(ctrl->status) + sizeof(uint8_t) * sum;
		vq->vq_split.ring.desc[i].len = dlen[k];
		sum += dlen[k];
		vq->vq_free_cnt--;
		i = vq->vq_split.ring.desc[i].next;
	}

	vq->vq_split.ring.desc[i].flags = VRING_DESC_F_WRITE;
	vq->vq_split.ring.desc[i].addr = cvq->virtio_net_hdr_mem
			+ sizeof(struct virtio_net_ctrl_hdr);
	vq->vq_split.ring.desc[i].len = sizeof(ctrl->status);
	vq->vq_free_cnt--;

	vq->vq_desc_head_idx = vq->vq_split.ring.desc[i].next;

	vq_update_avail_ring(vq, head);
	vq_update_avail_idx(vq);

	PMD_INIT_LOG(DEBUG, "vq->vq_queue_index = %d", vq->vq_queue_index);

	virtqueue_notify(vq);

	rte_rmb();
	while (VIRTQUEUE_NUSED(vq) == 0) {
		rte_rmb();
		usleep(100);
	}

	while (VIRTQUEUE_NUSED(vq)) {
		uint32_t idx, desc_idx, used_idx;
		struct vring_used_elem *uep;

		used_idx = (uint32_t)(vq->vq_used_cons_idx
				& (vq->vq_nentries - 1));
		uep = &vq->vq_split.ring.used->ring[used_idx];
		idx = (uint32_t)uep->id;
		desc_idx = idx;

		while (vq->vq_split.ring.desc[desc_idx].flags &
				VRING_DESC_F_NEXT) {
			desc_idx = vq->vq_split.ring.desc[desc_idx].next;
			vq->vq_free_cnt++;
		}

		vq->vq_split.ring.desc[desc_idx].next = vq->vq_desc_head_idx;
		vq->vq_desc_head_idx = idx;

		vq->vq_used_cons_idx++;
		vq->vq_free_cnt++;
	}

	PMD_INIT_LOG(DEBUG, "vq->vq_free_cnt=%d\nvq->vq_desc_head_idx=%d",
			vq->vq_free_cnt, vq->vq_desc_head_idx);

	result = cvq->virtio_net_hdr_mz->addr;
	return result;
}

int
virtio_send_command(struct virtnet_ctl *cvq, struct virtio_pmd_ctrl *ctrl,
		    int *dlen, int pkt_num)
{
	virtio_net_ctrl_ack status = ~0;
	struct virtio_pmd_ctrl *result;
	struct virtqueue *vq;

	ctrl->status = status;

	if (!cvq || !cvq->vq) {
		PMD_INIT_LOG(ERR, "Control queue is not supported.");
		return -1;
	}

	rte_spinlock_lock(&cvq->lock);
	vq = cvq->vq;

	PMD_INIT_LOG(DEBUG, "vq->vq_desc_head_idx = %d, status = %d, "
		"vq->hw->cvq = %p vq = %p",
		vq->vq_desc_head_idx, status, vq->hw->cvq, vq);

	if (vq->vq_free_cnt < pkt_num + 2 || pkt_num < 1) {
		rte_spinlock_unlock(&cvq->lock);
		return -1;
	}

	memcpy(cvq->virtio_net_hdr_mz->addr, ctrl,
		sizeof(struct virtio_pmd_ctrl));

	if (vtpci_packed_queue(vq->hw))
		result = virtio_send_command_packed(cvq, ctrl, dlen, pkt_num);
	else
		result = virtio_send_command_split(cvq, ctrl, dlen, pkt_num);

	rte_spinlock_unlock(&cvq->lock);
	return result->status;
}

void
virtio_init_vring(struct virtqueue *vq)
{
	int size = vq->vq_nentries;
	uint8_t *ring_mem = vq->vq_ring_virt_mem;

	PMD_INIT_FUNC_TRACE();

	memset(ring_mem, 0, vq->vq_ring_size);

	vq->vq_used_cons_idx = 0;
	vq->vq_desc_head_idx = 0;
	vq->vq_avail_idx = 0;
	vq->vq_desc_tail_idx = (uint16_t)(vq->vq_nentries - 1);
	vq->vq_free_cnt = vq->vq_nentries;
	if (vq->vq_descx)
		memset(vq->vq_descx, 0,
			sizeof(struct vq_desc_extra) * vq->vq_nentries);
	if (vtpci_packed_queue(vq->hw)) {
		vring_init_packed(&vq->vq_packed.ring, ring_mem,
				  VIRTIO_PCI_VRING_ALIGN, size);
		vring_desc_init_packed(vq, size);
	} else {
		struct vring *vr = &vq->vq_split.ring;

		vring_init_split(vr, ring_mem, VIRTIO_PCI_VRING_ALIGN, size);
		vring_desc_init_split(vr->desc, size);
	}
	/*
	 * Disable device(host) interrupting guest
	 */
	virtqueue_disable_intr(vq);
}
