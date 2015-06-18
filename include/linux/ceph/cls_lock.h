#ifndef _NET_CEPH_RADOS_LOCK_H
#define _NET_CEPH_RADOS_LOCK_H

enum CEPH_CLS_LOCK_TYPE {
	CEPH_CLS_LOCK_NONE = 0,
	CEPH_CLS_LOCK_EXCLUSIVE = 1,
	CEPH_CLS_LOCK_SHARED = 2,
};

int ceph_cls_lock(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		  char *lock_name, u8 type, char *cookie, char *tag, char *desc,
		  u8 flags);
int ceph_cls_unlock(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		    char *lock_name, char *cookie);
int ceph_cls_break_lock(struct ceph_osd_client *osdc, int poolid,
			char *obj_name, char *lock_name, u8 entity_type,
			u64 num, char *cookie);
#endif
