#ifndef _NET_CEPH_LIST_SNAPS_H
#define _NET_CEPH_LIST_SNAPS_H

#include <linux/ceph/messenger.h>
#include <linux/ceph/msgpool.h>
#include <linux/ceph/osd_client.h>
/*
 * struct obj_list_snap_response_t {
 *     vector {
 *         struct clone_info {
 *             snapid_t cloneid;
 *             vector<snapid_t> snaps;
 *             vector< pair<uint64_t, uint64_t> > overlap;
 *             uint64_t size;
 *         }
 *     }
 *     snapid_t seq;
 * }
 */

struct ceph_clone_overlap {
	u64 first;
	u64 second;
};

struct ceph_clone_info {
	u64 cloneid;
	size_t num_snaps;
	u64 *snaps;
	size_t num_overlaps;
	struct ceph_clone_overlap *overlaps;
	u64 size;
};

struct ceph_snap_list {
	u64 num_clones;
	struct ceph_clone_info *clones;
	u64 seq;
};

int ceph_osd_op_list_snaps(struct ceph_osd_client *osdc, int poolid,
			   const char *object_name,
			   struct ceph_snap_list *snaps);

void ceph_destroy_snap_list(struct ceph_snap_list *l);

#endif
