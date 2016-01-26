#include <linux/ceph/ceph_debug.h>

#include <linux/types.h>
#include <linux/slab.h>

#include <linux/ceph/list_snaps.h>
#include <linux/ceph/decode.h>
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

static int __decode_clone(struct ceph_clone_info *out, void **p, void *end)
{
	u32 len;
	int i;
	int ret;

	ret = ceph_start_decoding_compat(p, end, 1, 1, 1, &len);
	if (ret)
		return ret;

	ceph_decode_64_safe(p, end, out->cloneid, err);
	ceph_decode_32_safe(p, end, out->num_snaps, err);
	out->snaps = kmalloc_array(out->num_snaps, sizeof(u64), GFP_NOIO);
	if (!out->snaps) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < out->num_snaps; i++)
		ceph_decode_64_safe(p, end, out->snaps[i], err);

	ceph_decode_32_safe(p, end, out->num_overlaps, err);
	out->overlaps = kmalloc_array(out->num_overlaps,
				      sizeof(struct ceph_clone_overlap),
				      GFP_NOIO);
	if (!out->overlaps) {
		kfree(out->snaps);
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < out->num_overlaps; i++) {
		ceph_decode_64_safe(p, end, out->overlaps[i].first, err);
		ceph_decode_64_safe(p, end, out->overlaps[i].second, err);
	}

	ceph_decode_64_safe(p, end, out->size, err);
out:
	return ret;
err:
	return -EINVAL;
}

int ceph_osd_op_list_snaps(struct ceph_osd_client *osdc, int poolid,
			   const char *object_name,
			   struct ceph_snap_list *snaps)
{
	struct ceph_osd_request *osd_req;
	struct page *pg;
	u32 len;
	size_t num;
	void *p, *end;
	int i;
	int ret;

	pg = alloc_page(GFP_NOIO);
	if (!pg)
		return -ENOMEM;

	osd_req = ceph_osdc_alloc_request(osdc, NULL, 1, false, GFP_NOIO);
	if (!osd_req) {
		__free_page(pg);
		return -ENOMEM;
	}

	osd_req->r_flags = CEPH_OSD_FLAG_READ;
	osd_req->r_base_oloc.pool = poolid;
	osd_req->r_snapid = CEPH_SNAPDIR;
	ret = ceph_oid_aprintf(&osd_req->r_base_oid, GFP_NOIO, "%s",
			       object_name);
	if (ret)
		goto out;

	osd_req_op_init(osd_req, 0, CEPH_OSD_OP_LIST_SNAPS, 0);
	osd_req_op_list_snaps_response_data_pages(osd_req, 0, &pg, PAGE_SIZE,
						  0, false, false);
	ret = ceph_osdc_alloc_messages(osd_req, GFP_NOIO);
	if (ret)
		goto out;

	ret = ceph_osdc_start_request(osdc, osd_req, false);
	if (ret)
		goto out;

	ret = ceph_osdc_wait_request(osdc, osd_req);
	if (ret < 0)
		goto out;

	p = page_address(pg);
	end = p + osd_req->r_ops[0].outdata_len;

	ret = ceph_start_decoding_compat(&p, end, 2, 1, 1, &len);
	if (ret)
		goto err;

	ret = -ERANGE;
	ceph_decode_32_safe(&p, end, num, err);
	snaps->num_clones = num;
	snaps->clones = kmalloc_array(num, sizeof(struct ceph_clone_info),
				      GFP_NOIO);
	if (!snaps->clones) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num; i++) {
		ret = __decode_clone(snaps->clones + i, &p, end);
		if (ret)
			goto out;
	}

	ceph_decode_64_safe(&p, end, snaps->seq, err);

out:
	ceph_osdc_put_request(osd_req);
	return ret;
err:
	return -ENOMEM;
}
EXPORT_SYMBOL(ceph_osd_op_list_snaps);

void ceph_destroy_snap_list(struct ceph_snap_list *l)
{
	int i;

	for (i = 0; i < l->num_clones; i++) {
		kfree(l->clones[i].snaps);
		kfree(l->clones[i].overlaps);
	}

	kfree(l->clones);
}
EXPORT_SYMBOL(ceph_destroy_snap_list);
