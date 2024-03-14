#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/rbtree.h>
#include <linux/delay.h>

#include "cndrv_mm.h"
#include "cndrv_debug.h"
#include "cndrv_commu.h"

#include "cndrv_buddy_allocator.h"
#include "cndrv_genpool_allocator.h"
#include "cndrv_fa.h"
#include "camb_mm.h"
#include "camb_mm_rpc.h"
#include "camb_mm_pgretire.h"
#include "camb_mm_tools.h"

/*intenal func*/
static int __fa_info_cfg(struct cn_mm_set *mm_set, struct fa_init_info *info)
{
	mm_set->fa_watermark_dis = false;
	mm_set->fa_remote_ctrl = FA_RE_CTRL_NONE;
	info->devid = mm_set->devid;
	/* NOTES:
	 * It only supports CN_IPU_MEM/CN_CONST_MEM/CN_COMPRESS_MEM three types.
	 * And the affinity counter is 5 to compate mlu200s. And it supports 4 types
	 * cache mode. When the memory type is CONST or COMPRESS, it will use other
	 * bits for AP and compress modes.
	 */
	info->mem_type_cnt = 3;
	info->mem_affinity_cnt = 5;
	info->mem_flags = 4;
	/*NOTE:
	 *Mem free will reduce pool water level to high mark.
	 *Mem alloc will wake a workqueue. Set a timer will also wake workqueue.
	 *Fa watermark will keep water level in reasonable range
	 */
	info->low_watermark = FA_LOW_WATERMARK;
	info->high_watermark = FA_HIGH_WATERMARK;

	switch (mm_set->devid) {
	case MLUID_290:
	case MLUID_290V1:
	case MLUID_220:
	case MLUID_220_EDGE:
	case MLUID_270:
	case MLUID_270V:
	case MLUID_270V1:
		info->alloc_order = 9;
		info->chunk_size = 4 * 1024;
		info->alloc_size = 512;
		break;
	default:
		info->alloc_order = 13;
		info->chunk_size = 32 * 1024;
		info->alloc_size = 32 * 1024;
		break;
	}

	switch (mm_set->devid) {
	case  MLUID_PIGEON_EDGE:
	case  MLUID_CE3226_EDGE:
		/* fix some platform compile warning */
		mm_set->fa_watermark_dis = true;
		break;
	case  MLUID_590_DEV:
	case  MLUID_370_DEV:
		/* fix some platform compile warning */
		mm_set->fa_watermark_dis = true;
		mm_set->fa_remote_ctrl = FA_RE_CTRL_SERVER;
		break;
	case  MLUID_580:
	case  MLUID_580V:
	case  MLUID_590:
	case  MLUID_590V:
	case  MLUID_370:
	case  MLUID_370V:
		mm_set->fa_remote_ctrl = FA_RE_CTRL_CLIENT;
		break;
	default:
		break;
	}

	return 0;
}

/* According the fa pool id to get the mem_type. */
static int
__pool_id_to_mem_type(unsigned int pool_id, struct cn_fa_array *arr)
{
	int dim_type = pool_id / (arr->affinity * arr->flags);

	switch(dim_type) {
	case 0:
		return CN_IPU_MEM;
	case 1:
		return CN_CONST_MEM;
	case 2:
		return CN_COMPRESS_MEM;
	default:
		BUG_ON(1);
	}
}

/* According the mem params, such as mem_type, affinity and cache_mode,
 * to get the pool id of fa. */
int camb_fa_get_pool_id(unsigned int mem_type, unsigned int affinity,
			unsigned int flag, struct cn_fa_array *fa)
{
	int dim_type = 0;
	int pool_id;

	switch(mem_type) {
	case CN_IPU_MEM:
		dim_type = 0;
		break;
	case CN_CONST_MEM:
		dim_type = 1;
		break;
	case CN_COMPRESS_MEM:
		dim_type = 2;
		break;
	default:
		BUG_ON(1);
	}

	/* only to get the cache mode value even it has th AP and compress mode. */
	flag &= 0x3;
	pool_id = dim_type * fa->affinity * fa->flags + affinity * fa->flags + flag;

	return pool_id;
}


/* mem timer handle func for fa watermark*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void camb_watermark_timer_work(struct timer_list *timer)
{
	struct cn_mm_set *mm_set = container_of(timer, struct cn_mm_set,
											watermark_timer);
#else
static void camb_watermark_timer_work(unsigned long data)
{
	struct cn_mm_set *mm_set = (struct cn_mm_set *)data;
#endif
	queue_work(system_unbound_wq, &mm_set->fa_water_worker);

	mod_timer(&mm_set->watermark_timer, TIMER_EXPIRES_MSEC(1000 * 60 * 4));

	return;
}

void camb_fa_watermark_en(struct cn_fa_array *arr)
{
	struct cn_mm_set *mm_set = arr->mm_set;

	if (!mm_set->fa_watermark_dis) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
		timer_setup(&mm_set->watermark_timer, camb_watermark_timer_work, 0);
#else
		setup_timer(&mm_set->watermark_timer, camb_watermark_timer_work, (unsigned long)mm_set);
#endif
		mod_timer(&mm_set->watermark_timer, TIMER_EXPIRES_MSEC(1000 * 60 * 4));
	}
	return;
}

void camb_fa_watermark_disable(void *mem_set)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_fa_array *arr = mm_set->fa_array;

	if (!mm_set->fa_watermark_dis) {
		/* delete timer */
		del_timer_sync(&arr->mm_set->watermark_timer);
		/* cancel queue work */
		cancel_work_sync(&mm_set->fa_water_worker);
	}
	return;
}

static int camb_free_pool_rpc(struct cn_mm_set *mm_set,
						struct cn_fa_pool *pool,
						bool mem_sync_commu_point)
{
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	struct cn_fa_array *arr = mm_set->fa_array;
	struct ret_msg remsg;
	size_t dev_ret_len = sizeof(struct ret_msg);
	int ret = 0, j = 0, pgretire_status = 0, retry_times = 0;
	struct cn_fa_pool_chunk *chunk;
	struct list_head *_chunk, *_next_chunk;
	struct free_mem_list * free_list;
	int free_cnt = 0;
	int list_len = sizeof(struct free_mem_list) + sizeof(struct free_frame)
		* (FREE_LIST_MAX(core->support_ipcm) - 1);

	if (list_len > RPC_TRANS_MAX_LEN(core->support_ipcm)) {
		cn_dev_core_err(core, "mem free list len is large than commu limit");
		return -EINVAL;
	}

	free_list = cn_kzalloc(list_len, GFP_KERNEL);
	if (!free_list) {
		cn_dev_core_err(core, "kzalloc mem free transfer list space error!");
		return -ENOMEM;
	}

	pgretire_status = camb_set_pgretire_status(mm_set);
	free_list->extra_status = pgretire_status;
	remsg.extra_ret = 0;

	list_for_each_safe(_chunk, _next_chunk, &pool->chunks) {
		chunk = list_entry(_chunk, struct cn_fa_pool_chunk, next_chunk);
		if (camb_get_chunk_avail(arr, chunk) != (arr->chunk_size * 1024) >> pool->alloc_order) {
			cn_dev_core_debug(core, "Fa Mem addr %#llx is used, skip..",
							  chunk->start_addr);
			continue;
		}
		free_list->mem_cnt++;
		free_list->mem_list[j].tag = CN_IPU_MEM;
		free_list->mem_list[j].device_addr = chunk->start_addr;

		/*Whether commu is succeed or not, free fa chunk*/
		spin_lock(&pool->lock);
		list_del(&chunk->next_chunk);
		camb_chunk_destroy(arr, chunk);
		spin_unlock(&pool->lock);

		cn_kfree(chunk);
		cn_dev_core_debug(core, "Fa Mem free %#llx",
						  free_list->mem_list[j].device_addr);
		j++;
		/*if mem cnt is FREE_LIST_MAX or pos is last chunk, call commu free*/
		if (free_list->mem_cnt == FREE_LIST_MAX(core->support_ipcm)) {
			memset(&remsg, 0x0, sizeof(struct ret_msg));
rpc_free_retry1:
			if (mem_sync_commu_point) {/*sync*/
				ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_free",
									 free_list, list_len, &remsg,
									 &dev_ret_len, sizeof(struct ret_msg));

				if (ret < 0 ) {
					for (j = 0; j < free_list->mem_cnt; j++) {
						camb_add_node_free_failure_list(mm_set,
												   free_list->mem_list[j].device_addr,
												   NULL,
												   arr->chunk_size * 1024,
												   ret,
												   mem_sync_commu_point);
					}
				}
			} else {/*async*/
				ret = __mem_call_rpc(core, mm_set->mem_async_endpoint, "rpc_mem_free",
									 free_list, list_len, &remsg,
									 &dev_ret_len, sizeof(struct ret_msg));
				if (ret < 0 && ret != ERROR_RPC_RESET) {
					if (retry_times < MAX_FREE_RETRY_TIMES) {
						cn_dev_core_err(core, "camb_free_pool_rpc error status(ret:%d, "
										"remsg:%d), try again",	ret, remsg.ret);
						usleep_range(100, 200);
						retry_times++;
						goto rpc_free_retry1;
					} else {
						for (j = 0; j < free_list->mem_cnt; j++) {
							camb_add_node_free_failure_list(mm_set,
													   free_list->mem_list[j].device_addr,
													   NULL,
													   arr->chunk_size * 1024,
													   ret,
													   mem_sync_commu_point);
						}
						retry_times = 0;
					}
				}
			}

			if (ret) {
				cn_dev_core_err(core, "camb_free_mem_rpc error status(ret:%d, remsg:%d)",
								ret, remsg.ret);
			}
			free_cnt += free_list->mem_cnt;
			memset(free_list, 0x0, list_len);
			j = 0;
		}
	}

	if (free_list->mem_cnt) {
		memset(&remsg, 0x0, sizeof(struct ret_msg));
rpc_free_retry2:
		if (mem_sync_commu_point) {
			ret = __mem_call_rpc(core, mm_set->endpoint, "rpc_mem_free",
								 free_list, sizeof(struct free_mem_list) + sizeof(struct free_frame)
								 * (free_list->mem_cnt- 1), &remsg,
								 &dev_ret_len, sizeof(struct ret_msg));
			if (ret < 0 ) {
				for (j = 0; j < free_list->mem_cnt; j++) {
					camb_add_node_free_failure_list(mm_set,
											   free_list->mem_list[j].device_addr,
											   NULL,
											   arr->chunk_size * 1024,
											   ret,
											   mem_sync_commu_point);
				}
			}
		} else {
			ret = __mem_call_rpc(core, mm_set->mem_async_endpoint, "rpc_mem_free",
								 free_list, sizeof(struct free_mem_list) + sizeof(struct free_frame)
								 * (free_list->mem_cnt- 1), &remsg,
								 &dev_ret_len, sizeof(struct ret_msg));
			if (ret < 0 && ret != ERROR_RPC_RESET) {
				if (retry_times < MAX_FREE_RETRY_TIMES) {
					cn_dev_core_err(core, "camb_free_pool_rpc error status(ret:%d, "
									"remsg:%d), try again",	ret, remsg.ret);
					usleep_range(100, 200);
					retry_times++;
					goto rpc_free_retry2;
				} else {
					for (j = 0; j < free_list->mem_cnt; j++) {
						camb_add_node_free_failure_list(mm_set,
												   free_list->mem_list[j].device_addr,
												   NULL,
												   arr->chunk_size * 1024,
												   ret,
												   mem_sync_commu_point);
					}
					retry_times = 0;
				}
			}
		}

		if (ret) {
			cn_dev_core_err(core, "camb_free_mem_rpc error status(ret:%d, remsg:%d)",
							ret, remsg.ret);
		}
		free_cnt += free_list->mem_cnt;
	}

	camb_get_pgretire_result(mm_set, pgretire_status, remsg.extra_ret);

	cn_kfree(free_list);

	return free_cnt;
}

struct cn_fa_pool *camb_fa_pool_create(struct cn_fa_array *arr, int alloc_order)
{
	struct cn_fa_pool *pool = NULL;

	pool = cn_kzalloc(sizeof(struct cn_fa_pool), GFP_KERNEL);

	if (pool != NULL) {
		spin_lock_init(&pool->lock);
		INIT_LIST_HEAD(&pool->chunks);
		INIT_LIST_HEAD(&pool->unused_chunks);

		pool->alloc_order = alloc_order;

		pool->arr = arr;
		pool->shortest_chunk = NULL;
		atomic_set(&pool->longest, 0);
		atomic_set(&pool->chunk_cnt, 0);
		atomic_set(&pool->free_chunk_cnt, 0);
		atomic_set(&pool->shortest, 0xFFFFFFFF);
		mutex_init(&pool->chunk_lock);
		mutex_init(&pool->rpc_times);
	} else {
		return NULL;
	}

	return pool;
}

int camb_fa_pool_add_chunk(struct cn_fa_array *arr,
						 struct cn_fa_pool *pool, struct mem_attr *pattr)
{
	return arr->fa_ops->camb_fa_pool_add_chunk(arr, pool, pattr);
}

int camb_fa_mask_chunks(struct cn_fa_array *arr)
{
	return arr->fa_ops->camb_fa_mask_chunks(arr);
}

void camb_fa_reset_count(struct cn_fa_array *arr, struct cn_fa_pool *pool)
{
	arr->fa_ops->camb_reset_count(arr, pool);
}

dev_addr_t camb_fa_alloc(struct cn_fa_array *arr, struct mem_attr *attr,
					   size_t size,
					   void *fa_priv)
{
	return arr->fa_ops->camb_fa_alloc(arr, attr, size, fa_priv);
}

int camb_fa_free(struct cn_fa_array *arr, void *fa_priv)
{
	int ret = 0;

	ret = arr->fa_ops->camb_fa_free(arr, fa_priv);
	camb_fa_clear_unused(arr);

	return ret;
}

unsigned int camb_get_chunk_avail(struct cn_fa_array *arr,
								struct cn_fa_pool_chunk *chunk)
{
	return arr->fa_ops->camb_get_chunk_avail(arr, chunk);
}

void camb_chunk_destroy(struct cn_fa_array *arr,
					  struct cn_fa_pool_chunk *chunk)
{
	return arr->fa_ops->camb_chunk_destroy(arr, chunk);
}

unsigned int camb_fixsize(struct cn_fa_array *arr,
				unsigned int size)
{
	return arr->fa_ops->camb_fixsize(arr, size);
}

struct fa_plat_sp_ops *camb_fa_set_plat_ops(unsigned int devid)
{
	struct fa_plat_sp_ops *fa_ops;

	fa_ops = cn_kzalloc(sizeof(struct fa_plat_sp_ops), GFP_KERNEL);
	if (unlikely(fa_ops == NULL)) {
		return NULL;
	}

	switch(devid) {
	case MLUID_290:
	case MLUID_290V1:
	case MLUID_270:
	case MLUID_220:
	case MLUID_220_EDGE:
	case MLUID_270V:
	case MLUID_270V1:
		buddy_fa_ops_register(fa_ops);
		break;
	default:
		genpool_fa_ops_register(fa_ops);
		break;
	}

	return fa_ops;
}

/**
 * camb_fast_alloc_init - create a new memory pool array
 * @core:
 * @alloc_order: log base 2 of number of bytes each bitmap bit represents
 *
 * Create a new special memory pool that can be used to manage special purpose
 * memory not managed by the regular kzalloc/kfree interface.
 */
struct cn_fa_array *camb_fast_alloc_init(struct cn_core_set *core, struct fa_init_info *info)
{
	int i;
	struct cn_fa_array *arr;

	arr = cn_kzalloc(sizeof(struct cn_fa_array) +
					 info->mem_type_cnt * info->mem_affinity_cnt *
					 info->mem_flags * sizeof(struct cn_fa_pool *), GFP_KERNEL);

	if (arr != NULL) {
		arr->core = core;
		arr->mm_set = core->mm_set;
		arr->low_watermark = info->low_watermark;
		arr->high_watermark = info->high_watermark;
		arr->type = info->mem_type_cnt;
		arr->affinity = info->mem_affinity_cnt;
		arr->flags = info->mem_flags;
		arr->alloc_order = info->alloc_order;
		arr->chunk_size = info->chunk_size;
		arr->alloc_size = info->alloc_size;
		arr->total_chunk = 0;
		atomic_set(&arr->total_free_chunk, 0);
		arr->used_mem = 0;
		arr->enable = 1;
		spin_lock_init(&arr->lock);

		arr->fa_ops = camb_fa_set_plat_ops(info->devid);
		if (arr->fa_ops == NULL) {
			cn_kfree(arr);
			return NULL;
		}

		for (i = 0; i < arr->type * arr->affinity * arr->flags; i++) {
			arr->pool[i] = camb_fa_pool_create(arr, info->alloc_order);
			if (arr->pool[i] != NULL) {
				arr->pool[i]->arr = arr;
				arr->pool[i]->mm_attr.type = __pool_id_to_mem_type(i, arr);
				arr->pool[i]->mm_attr.affinity = (i % (arr->affinity * arr->flags)) / arr->flags;
				arr->pool[i]->mm_attr.flag = i % arr->flags;
				arr->pool[i]->mm_attr.vmid = PF_ID;
				arr->pool[i]->mm_set = core->mm_set;
				arr->pool[i]->low_watermark = info->low_watermark;
				arr->pool[i]->high_watermark = info->high_watermark;
			} else {
				cn_dev_core_err(core, "FA pool init err");
				for (i = 0; i < arr->type * arr->affinity * arr->flags; i++) {
					if (arr->pool[i]) {
						cn_kfree(arr->pool[i]);
					}
				}
				cn_kfree(arr->fa_ops);
				cn_kfree(arr);
				return NULL;
			}
		}

	} else {
		cn_dev_core_err(core, "FA Array init err");
		return NULL;
	}

	return arr;
}

void camb_fast_alloc_exit(struct cn_fa_array *arr)
{
	int i;

	cn_dev_core_debug(arr->core, "arr->type = %u, arr->affinity = %u, arr->flags = %u",
					  arr->type, arr->affinity, arr->flags);

	camb_fa_watermark_disable(arr->mm_set);

	for (i = 0; i < arr->type * arr->affinity * arr->flags; i++) {
		cn_kfree(arr->pool[i]);
	}
	cn_kfree(arr->fa_ops);
	cn_kfree(arr);
}

static void
__fa_chunk_gather_locked(struct cn_fa_array *arr, struct cn_fa_pool *pool_in,
			struct list_head *chunks_list, struct cn_fa_pool *pool_out)
{
	struct cn_fa_pool_chunk *chunk;
	struct list_head *_chunk, *_next_chunk;

	list_for_each_safe(_chunk, _next_chunk, chunks_list) {
		chunk = list_entry(_chunk, struct cn_fa_pool_chunk, next_chunk);
		if (camb_get_chunk_avail(arr, chunk) ==
			(arr->chunk_size * 1024) >> pool_in->alloc_order) {
			list_del(&chunk->next_chunk);
			list_add(&chunk->next_chunk, &pool_out->chunks);
			atomic_inc(&pool_out->chunk_cnt);
			atomic_dec(&pool_in->chunk_cnt);
			camb_fa_reset_count(arr, pool_in);
			/*arr total_free_chunk dec in reset_count*/
			atomic_inc(&arr->total_free_chunk);
		}
	}
}

static void camb_fa_chunk_gather(struct cn_fa_pool *pool,
								struct cn_fa_array *arr, int shrink_list)
{
	int i = 0;

	for (i = 0; i < arr->type * arr->affinity * arr->flags; i++) {
		/* Find all the free chunks */
		spin_lock(&arr->pool[i]->lock);
		if (shrink_list & NORMAL_LIST) {
			__fa_chunk_gather_locked(arr, arr->pool[i],
							&arr->pool[i]->chunks, pool);
		}

		if (!(shrink_list & UNUSED_LIST) ||
			list_empty(&arr->pool[i]->unused_chunks)) {
			spin_unlock(&arr->pool[i]->lock);
			continue;
		}

		__fa_chunk_gather_locked(arr, arr->pool[i],
						&arr->pool[i]->unused_chunks, pool);
		spin_unlock(&arr->pool[i]->lock);
		/* Find all the free chunks End */
	}

	return;
}

/*external api*/

int camb_fa_statistic(struct cn_fa_array *arr, struct fa_stat *stat)
{
	if ((!arr) || (!stat))
		return -EINVAL;

	spin_lock(&arr->lock);

	stat->total_size = arr->total_chunk * arr->chunk_size * 1024;
	stat->used_size = arr->used_mem << arr->alloc_order;
	stat->require_mem = arr->require_mem;

	spin_unlock(&arr->lock);
	stat->shrink_size = (atomic_read(&arr->total_free_chunk)) * arr->chunk_size * 1024;

	return 0;
}

#ifdef CONFIG_CNDRV_PCIE_ARM_PLATFORM
int camb_arm_fa_dev_ops(struct fa_dev_ops *fa_data)
{
	int cmd, ret = 0, en;
	struct cn_core_set *core;
	struct cn_mm_set *mm_set;

	/*FIXME: As describe in [DRIVER-8054]. In virt situation, cndv_host program
	 * which run in device, could not achieve to be completely isolated by core.
	 * So all virtual machine is regarded as different pthread in fa_array.
	 */
	core = (struct cn_core_set *)cn_core_get_with_idx(0);
	if (!core) {
		cn_dev_err("MemAdj:It's failed to get core_set with 0)!");
		return -EINVAL;
	}
	mm_set = (struct cn_mm_set *)core->mm_set;

	cmd = fa_data->cmd;
	if (mm_set->fa_remote_ctrl != FA_RE_CTRL_SERVER) {
		cn_dev_core_err(core, "FA dev ops could not run in plat %x type %d",
						mm_set->devid, mm_set->fa_remote_ctrl);
		return -EINVAL;
	}

	switch (cmd) {
	case FA_OPS_GET_STAT:
		ret = camb_fa_statistic(mm_set->fa_array, &fa_data->stat);
		break;
	case FA_OPS_CTL_EN:
		en = fa_data->en;
		camb_fa_ctrl((void*)mm_set, en);
		break;
	case FA_OPS_MASK_CHUNKS:
		camb_fa_mask_chunks(mm_set->fa_array);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
#endif

/**
 * camb_fa_shrink - free fa unnecessary pool chunks
 *
 *	@free_all_mem: free all unused chunk in pools.
 */

static void camb_fa_shrink_list(struct cn_mm_set *mm_set,
								struct cn_fa_array *arr, int shrink_list,
								bool mem_sync_commu_point)
{
	struct cn_fa_pool *pool;
	struct cn_core_set *core = (struct cn_core_set *)mm_set->core;
	unsigned int rpc_free_cnt;

	pool = camb_fa_pool_create(arr, arr->alloc_order);
	if (pool == NULL) {
		cn_dev_core_err(core, "FA pool init err");
		return;
	}

	camb_fa_chunk_gather(pool, arr, shrink_list);

	rpc_free_cnt = camb_free_pool_rpc(mm_set, pool, mem_sync_commu_point);

	cn_dev_core_debug(core, "Fa pool chunk cnt %d", rpc_free_cnt);

	/* Update arr Statistics */
	if (rpc_free_cnt > 0) {
		spin_lock(&arr->lock);
		arr->total_chunk -= rpc_free_cnt;
		spin_unlock(&arr->lock);
		atomic_sub(rpc_free_cnt, &arr->total_free_chunk);
	}

	cn_kfree(pool);

	return;
}

void camb_fa_shrink(struct cn_mm_set *mm_set,
			struct cn_fa_array *arr, bool mem_sync_commu_point)
{
	camb_fa_shrink_list(mm_set, arr, NORMAL_LIST | UNUSED_LIST, mem_sync_commu_point);
}

void camb_fa_clear_unused(struct cn_fa_array *arr)
{
	struct cn_mm_set *mm_set = arr->mm_set;

	if (!mm_set->pgretire_enable && !mm_set->pgretire_server_enable)
		return ;

	camb_fa_shrink_list(mm_set, arr, UNUSED_LIST, true);
}

int camb_fa_ctrl(void *mem_set, unsigned int en)
{
	struct cn_mm_set *mm_set = mem_set;
	struct cn_core_set *core = mm_set->core;
	struct cn_fa_array *arr = mm_set->fa_array;

	/*cmd is enable and fa state is disable*/
	if (en == MEM_FA_ENABLE && arr->enable == 0) {
		camb_fa_watermark_en(arr);
		arr->enable = 1;
		cn_dev_core_info(core, "FA enabled.");
		camb_mem_fa_dev_ctrl(mem_set, en);
		/*cmd is disable and fa state is enable*/
	} else if (en == MEM_FA_DISABLE && arr->enable == 1) {
		arr->enable = 0;
		camb_fa_watermark_disable(mem_set);
		camb_fa_shrink(mm_set, arr, true);
		cn_dev_core_info(core, "FA disabled.");
		camb_mem_fa_dev_ctrl(mem_set, en);
	} else if (en == 3) {
		camb_fa_shrink(mm_set, arr, true);
		cn_dev_core_info(core, "FA clear.");
	}
	return 0;
}

void camb_fa_water_handle(struct work_struct *work)
{
	struct cn_mm_set *mm_set = container_of(work, struct cn_mm_set,
											fa_water_worker);
	struct cn_fa_array *arr = mm_set->fa_array;

	camb_fa_shrink(mm_set, arr, false);
}

int camb_fa_init(void *pcore)
{
	struct cn_core_set *core = (struct cn_core_set *)pcore;
	struct cn_mm_set *mm_set = (struct cn_mm_set *)core->mm_set;
	struct fa_init_info info;

	__fa_info_cfg(mm_set, &info);
	mm_set->fa_array = camb_fast_alloc_init(core, &info);
	if (mm_set->fa_array == NULL) {
		cn_dev_core_err(core, "FA init failed.");
		return -ENOMEM;
	}

	if (!mm_set->fa_watermark_dis) {
		INIT_WORK(&mm_set->fa_water_worker, camb_fa_water_handle);
		/*set timer interval as 4 min*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
		timer_setup(&mm_set->watermark_timer, camb_watermark_timer_work, 0);
#else
		setup_timer(&mm_set->watermark_timer, camb_watermark_timer_work, (unsigned long)mm_set);
#endif
		mod_timer(&mm_set->watermark_timer, TIMER_EXPIRES_MSEC(1000 * 60 * 4));
	}

	#ifdef CONFIG_CNDRV_PCIE_ARM_PLATFORM
	if (mm_set->fa_remote_ctrl == FA_RE_CTRL_SERVER) {
		cn_dev_core_info(core, "FA register remote ops in dev");
		__mem_call_rpc(core, NULL, "cvms_arm_fa_dev_ops_cbk_register",
									 camb_arm_fa_dev_ops, sizeof(&camb_arm_fa_dev_ops), NULL,
									 NULL, 0);
	}
	#endif
	return 0;
}
