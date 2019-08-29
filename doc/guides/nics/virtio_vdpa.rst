..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Red Hat, Inc.

Virtio vDPA driver
==================

The Virtio vDPA driver provides support to either para-virtualized
or fully HW offloaded Virtio-net devices.

Pre-Installation Configuration
------------------------------

Config File Options
~~~~~~~~~~~~~~~~~~~

The following option can be modified in the ``config`` file.

- ``CONFIG_RTE_VIRTIO_VDPA`` (default ``y`` for linux)

Virtio vDPA Implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~

To let the Virtio-net device being probed by the Virtio vDPA driver, adding
"vdpa=1" parameter helps to specify that this device is to be used in vDPA
mode, rather than polling mode, virtio pmd will skip when it detects this
message. If no specified, device will not be used as a vDPA device, and it
will be driven by virtio pmd.

This driver requires the use of VFIO with IOMMU enabled, as a second level
of addresses translation is required.

Features
--------

Features of the Virtio vDPA driver are:

- Compatibility with virtio 0.95, 1.0 and 1.1.
- Multiqueue support.

Prerequisites
-------------

- Platform with IOMMU feature. Virtio device needs address translation
  service to Rx/Tx directly with virtio driver in VM or container.

