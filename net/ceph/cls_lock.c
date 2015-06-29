#include <linux/ceph/ceph_debug.h>

#include <linux/types.h>
#include <linux/slab.h>

#include <linux/ceph/cls_lock.h>
#include <linux/ceph/auth.h>
#include <linux/ceph/decode.h>
#include <linux/ceph/messenger.h>
#include <linux/ceph/msgpool.h>
#include <linux/ceph/osd_client.h>

static int __decode_locker(struct ceph_locker *locker, void **p, void *end)
{
	/*
	 * struct cls_lock_get_info_reply {
	 *     map {
	 *         struct locker_id_t {
	 *             struct entity_name_t {
	 *                 __u8 type;
	 *                 int64_t num;
	 *             }
	 *             string cookie;
	 *         }
	 *         struct locker_info_t {
	 *             struct timespec ts;
	 *			struct ceph_entity_addr addr;
	 *			string description;
	 *         }
	 *     }
	 *     int8_t lock_type;
	 *     string tag;
	 * }
	 */
	int ret;
	u32 len;

	/* locker_id_t */
	ret = ceph_start_decoding_compat(p, end, 1, 1, 1, &len);
	if (ret)
		return ret;

	ret = ceph_entity_name_decode(&locker->id.name, p, end);
	if (ret)
		return ret;

	locker->id.cookie = ceph_extract_encoded_string(p, end,
							&locker->id.cookie_len,
							GFP_NOIO);
	if (IS_ERR(locker->id.cookie))
		return PTR_ERR(locker->id.cookie);

	/* locker_info_t */
	ret = ceph_start_decoding_compat(p, end, 1, 1, 1, &len);
	if (ret)
		goto free_cookie;

	ceph_decode_timespec(&locker->info.ts, *p);
	*p += sizeof(struct ceph_timespec);

	ret = -ERANGE;
	ceph_decode_copy_safe(p, end, &locker->info.addr,
			      sizeof(locker->info.addr), free_cookie);
	ceph_decode_addr(&locker->info.addr);

	locker->info.desc = ceph_extract_encoded_string(p, end,
							&locker->info.desc_len,
							GFP_NOIO);
	if (IS_ERR(locker->info.desc)) {
		ret = PTR_ERR(locker->info.desc);
		goto free_cookie;
	}

	return 0;

free_cookie:
	kfree(locker->id.cookie);
	return ret;
}

int ceph_cls_lock_info(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		       char *lock_name, int *num_lockers,
		       struct ceph_locker **lockers, u8 *lock_type, char **tag)
{
	int get_info_op_buf_size;
	int name_len = strlen(lock_name);
	struct page *get_info_page;
	struct page *reply_page;
	size_t reply_len;
	int len;
	u32 num;
	void *p, *end;
	int ret;
	int i;

	get_info_op_buf_size = name_len + sizeof(__le32) +
			       CEPH_ENCODING_START_BLK_LEN;
	if (get_info_op_buf_size > PAGE_SIZE)
		return -ERANGE;

	get_info_page = alloc_page(GFP_NOIO);
	if (!get_info_page)
		return -ENOMEM;

	reply_page = alloc_page(GFP_NOIO);
	if (!reply_page) {
		__free_page(get_info_page);
		return -ENOMEM;
	}

	p = page_address(get_info_page);
	end = p + get_info_op_buf_size;

	ceph_start_encoding(&p, 1, 1,
			    get_info_op_buf_size - CEPH_ENCODING_START_BLK_LEN);

	ceph_encode_string(&p, end, lock_name, name_len);

	dout("%s: lock info for %s on object %s\n",
	     __func__, lock_name, obj_name);

	ret = ceph_osdc_cls_call(osdc, poolid, obj_name, "lock", "get_info",
				 CEPH_OSD_FLAG_READ, &get_info_page,
				 get_info_op_buf_size, &reply_page, &reply_len);

	dout("%s: status %d\n", __func__, ret);
	if (ret < 0)
		goto err;

	p = page_address(reply_page);
	end = p + reply_len;

	ret = ceph_start_decoding_compat(&p, end, 1, 1, 1, &len);
	if (ret)
		goto err;

	ret = -ERANGE;
	ceph_decode_32_safe(&p, end, num, err);
	*num_lockers = (int)num;

	*lockers = kcalloc(num, sizeof(**lockers), GFP_NOIO);
	if (!*lockers) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < num; i++) {
		ret = __decode_locker(*lockers + i, &p, end);
		if (ret)
			goto free_lockers;
	}

	ceph_decode_8_safe(&p, end, *lock_type, free_lockers);
	*tag = ceph_extract_encoded_string(&p, end, NULL, GFP_NOIO);

	if (IS_ERR(tag)) {
		ret = PTR_ERR(tag);
		goto free_lockers;
	}

	ret = 0;

err:
	__free_page(get_info_page);
	__free_page(reply_page);
	return ret;

free_lockers:
	kfree(*lockers);
	goto err;
}
EXPORT_SYMBOL(ceph_cls_lock_info);

/**
 * ceph_cls_lock - grab rados lock for object
 *  @osdc, @poolid, @obj_name: object to lock
 *  @lock_name: the name of the lock
 *  @type: lock type (RADOS_LOCK_EXCLUSIVE or RADOS_LOCK_SHARED)
 *  @cookie: user-defined identifier for this instance of the lock
 *  @tag: if RADOS_LOCK_SHARED, tag of the lock. NULL if non shared.
 *  @desc: user-defined lock description
 *  @flags: lock flags
 */
int ceph_cls_lock(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		  char *lock_name, u8 type, char *cookie, char *tag, char *desc,
		  u8 flags)
{
	int lock_op_buf_size;
	int name_len = strlen(lock_name);
	int cookie_len = strlen(cookie);
	int tag_len = strlen(tag);
	int desc_len = strlen(desc);
	void *p, *end;
	struct page *lock_op_page;
	struct timespec mtime;
	int ret;

	lock_op_buf_size = name_len + sizeof(__le32) +
				cookie_len + sizeof(__le32) +
				tag_len + sizeof(__le32) +
				desc_len + sizeof(__le32) +
				sizeof(mtime) +
				/* flag and type */
				sizeof(u8) + sizeof(u8) +
				CEPH_ENCODING_START_BLK_LEN;
	BUG_ON(lock_op_buf_size > PAGE_SIZE);
	lock_op_page = alloc_page(GFP_NOIO);
	if (!lock_op_page)
		return -ENOMEM;

	p = page_address(lock_op_page);
	end = p + lock_op_buf_size;

	ceph_start_encoding(&p, 1, 1,
			    lock_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	/* encode cls_lock_lock_op struct */
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_8(&p, type);
	ceph_encode_string(&p, end, cookie, cookie_len);
	ceph_encode_string(&p, end, tag, tag_len);
	ceph_encode_string(&p, end, desc, desc_len);
	/* only support infinite duration */
	memset(&mtime, 0, sizeof(mtime));
	ceph_encode_timespec(p, &mtime);
	p += sizeof(struct ceph_timespec);
	ceph_encode_8(&p, flags);

	dout("%s: %s %d %s %s %s %d\n", __func__,
	     lock_name, type, cookie, tag, desc, flags);

	ret = ceph_osdc_cls_call(osdc, poolid, obj_name, "lock", "lock",
				 CEPH_OSD_FLAG_WRITE | CEPH_OSD_FLAG_ONDISK,
				 &lock_op_page, lock_op_buf_size, NULL, 0);

	dout("%s: status %d\n", __func__, ret);
	__free_page(lock_op_page);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_lock);

/**
 * ceph_cls_unlock - release rados lock for object
 *  @osdc, @poolid, @obj_name: object to lock
 *  @lock_name: the name of the lock
 *  @cookie: user-defined identifier for this instance of the lock
 */
int ceph_cls_unlock(struct ceph_osd_client *osdc, int poolid, char *obj_name,
		    char *lock_name, char *cookie)
{
	int unlock_op_buf_size;
	int name_len = strlen(lock_name);
	int cookie_len = strlen(cookie);
	void *p, *end;
	struct page *unlock_op_page;
	int ret;

	unlock_op_buf_size = name_len + sizeof(__le32) +
			     cookie_len + sizeof(__le32) +
			     CEPH_ENCODING_START_BLK_LEN;
	BUG_ON(unlock_op_buf_size > PAGE_SIZE);
	unlock_op_page = alloc_page(GFP_NOIO);
	if (!unlock_op_page)
		return -ENOMEM;

	p = page_address(unlock_op_page);
	end = p + unlock_op_buf_size;

	ceph_start_encoding(&p, 1, 1,
			    unlock_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	/* encode cls_lock_unlock_op struct */
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_string(&p, end, cookie, cookie_len);

	dout("%s: %s %s\n", __func__, lock_name, cookie);
	ret = ceph_osdc_cls_call(osdc, poolid, obj_name, "lock", "unlock",
				 CEPH_OSD_FLAG_WRITE | CEPH_OSD_FLAG_ONDISK,
				 &unlock_op_page, unlock_op_buf_size, NULL, 0);

	dout("%s: status %d\n", __func__, ret);
	__free_page(unlock_op_page);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_unlock);

/**
 * ceph_cls_break_lock - release rados lock for object for specified client
 *  @osdc, @poolid, @obj_name: object to lock
 *  @lock_name: the name of the lock
 *  @entity_type: ceph entity type (CEPH_ENTITY_TYPE_*)
 *  @num: ceph entity id
 *  @cookie: user-defined identifier for this instance of the lock
 */
int ceph_cls_break_lock(struct ceph_osd_client *osdc, int poolid,
			char *obj_name, char *lock_name, u8 entity_type,
			u64 num, char *cookie)
{
	int break_lock_op_buf_size;
	int name_len = strlen(lock_name);
	int cookie_len = strlen(cookie);
	struct page *break_lock_op_page;
	void *p, *end;
	int ret;

	break_lock_op_buf_size = name_len + sizeof(__le32) +
				 cookie_len + sizeof(__le32) +
				 sizeof(u8) + sizeof(__le64) +
				 CEPH_ENCODING_START_BLK_LEN;
	BUG_ON(break_lock_op_buf_size > PAGE_SIZE);
	break_lock_op_page = alloc_page(GFP_NOIO);
	if (!break_lock_op_page)
		return -ENOMEM;

	p = page_address(break_lock_op_page);
	end = p + break_lock_op_buf_size;

	ceph_start_encoding(&p, 1, 1,
			break_lock_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	/* encode cls_lock_break_op struct */
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_8(&p, entity_type);
	ceph_encode_64(&p, num);
	ceph_encode_string(&p, end, cookie, cookie_len);

	dout("%s: lock %s entity_type %hu id %llu cookie %s\n",
	     __func__, lock_name, entity_type, num, cookie);

	ret = ceph_osdc_cls_call(osdc, poolid, obj_name, "lock", "break_lock",
				 CEPH_OSD_FLAG_WRITE | CEPH_OSD_FLAG_ONDISK,
				 &break_lock_op_page, break_lock_op_buf_size,
				 NULL, 0);

	dout("%s: status %d\n", __func__, ret);
	__free_page(break_lock_op_page);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_break_lock);
