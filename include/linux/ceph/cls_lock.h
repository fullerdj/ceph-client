#ifndef _NET_CEPH_RADOS_LOCK_H
#define _NET_CEPH_RADOS_LOCK_H

#include <linux/ceph/types.h>
#include <linux/ceph/msgpool.h>
#include <linux/ceph/messenger.h>
#include <linux/ceph/osdmap.h>
#include <linux/ceph/osd_client.h>

enum CEPH_CLS_LOCK_TYPE {
	CEPH_CLS_LOCK_NONE = 0,
	CEPH_CLS_LOCK_EXCLUSIVE = 1,
	CEPH_CLS_LOCK_SHARED = 2,
};

struct ceph_locker_id {
	struct ceph_entity_name name;
	size_t cookie_len;
	char *cookie;
};

struct ceph_locker_info {
	struct timespec ts;
	struct ceph_entity_addr addr;
	size_t desc_len;
	char *desc;
};

struct ceph_locker {
	struct ceph_locker_id id;
	struct ceph_locker_info info;
};

int ceph_cls_lock_info(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		       char *lock_name, int *num_lockers,
		       struct ceph_locker **lockers, u8 *lock_type, char **tag);
int ceph_cls_lock(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		  char *lock_name, u8 type, char *cookie, char *tag, char *desc,
		  u8 flags);
int ceph_cls_unlock(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		    char *lock_name, char *cookie);
int ceph_cls_break_lock(struct ceph_osd_client *osdc, int poolid,
			char *obj_name, char *lock_name, u8 entity_type,
			u64 num, char *cookie);
#endif
