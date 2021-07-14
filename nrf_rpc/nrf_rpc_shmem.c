#define NRF_RPC_LOG_MODULE NRF_RPC_TR
#include <nrf_rpc_log.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "nrf_rpc_os.h"
#include "nrf_rpc_shmem.h"
#include "nrf_rpc_common.h"


#define FLAG_RELEASE 0x80

#define WORD_SIZE sizeof(uint32_t)
#define WORD_BITS (8 * sizeof(uint32_t))

#if defined(CONFIG_NRF_RPC_SHMEM_NUM_BLOCKS_32)
typedef uint32_t mask_t;
typedef int32_t smask_t;
#define NUM_BLOCKS 32
#define mask_clz nrf_rpc_os_clz32
#elif defined(CONFIG_NRF_RPC_SHMEM_NUM_BLOCKS_64)
typedef uint64_t mask_t;
typedef int64_t smask_t;
#define NUM_BLOCKS 64
#define mask_clz nrf_rpc_os_clz64
#else
#error Number of shared dynamic memory blocks is not configured.
#endif

#define ALLOCABLE_MULTIPLY (WORD_SIZE * NUM_BLOCKS)

#define OUT_TOTAL_SIZE CONFIG_NRF_RPC_SHMEM_OUT_SIZE
#define OUT_ALLOCABLE_SIZE (((OUT_TOTAL_SIZE - (2 * WORD_SIZE + 2 * NUM_BLOCKS + 1 + 1)) / ALLOCABLE_MULTIPLY) * ALLOCABLE_MULTIPLY)
#define OUT_QUEUE_SIZE (OUT_TOTAL_SIZE - OUT_ALLOCABLE_SIZE - 1)
#define OUT_QUEUE_ITEMS (OUT_QUEUE_SIZE - 2 * WORD_SIZE)
#define OUT_BLOCK_SIZE (OUT_ALLOCABLE_SIZE / NUM_BLOCKS)

#define IN_TOTAL_SIZE CONFIG_NRF_RPC_SHMEM_IN_SIZE
#define IN_ALLOCABLE_SIZE (((IN_TOTAL_SIZE - (2 * WORD_SIZE + 2 * NUM_BLOCKS + 1 + 1)) / ALLOCABLE_MULTIPLY) * ALLOCABLE_MULTIPLY)
#define IN_QUEUE_SIZE (IN_TOTAL_SIZE - IN_ALLOCABLE_SIZE - 1)
#define IN_QUEUE_ITEMS (IN_QUEUE_SIZE - 2 * WORD_SIZE)
#define IN_BLOCK_SIZE (IN_ALLOCABLE_SIZE / NUM_BLOCKS)

#define QUEUE_INDEX_MASK (NUM_BLOCKS - 1)

#if NRF_RPC_OS_SHMEM_PTR_CONST

static uint8_t *const out_allocable = (uint8_t *)nrf_rpc_os_out_shmem_ptr;
static uint32_t *const out_queue_tx = (uint32_t *)&out_allocable[OUT_ALLOCABLE_SIZE];
static uint32_t *const out_queue_rx = (uint32_t *)&out_allocable[OUT_ALLOCABLE_SIZE + WORD_SIZE];
static uint8_t *const out_queue = (uint8_t *)&out_allocable[OUT_ALLOCABLE_SIZE + 2 * WORD_SIZE];
static uint8_t *const out_handshake = (uint8_t *)&out_allocable[OUT_TOTAL_SIZE - 1];

static uint8_t *const in_allocable = (uint8_t *)nrf_rpc_os_in_shmem_ptr;
static uint32_t *const in_queue_tx = (uint32_t *)&in_allocable[IN_ALLOCABLE_SIZE];
static uint32_t *const in_queue_rx = (uint32_t *)&in_allocable[IN_ALLOCABLE_SIZE + WORD_SIZE];
static uint8_t *const in_queue = (uint8_t *)&in_allocable[IN_ALLOCABLE_SIZE + 2 * WORD_SIZE];
static uint8_t *const in_handshake = (uint8_t *)&in_allocable[IN_TOTAL_SIZE - 1];

#else

static uint8_t * out_allocable;
static uint32_t * out_queue_tx;
static uint32_t * out_queue_rx;
static uint8_t * out_queue;
static uint8_t * out_handshake;

static uint8_t * in_allocable;
static uint32_t * in_queue_tx;
static uint32_t * in_queue_rx;
static uint8_t * in_queue;
static uint8_t * in_handshake;

#endif

static nrf_rpc_os_sem_t out_sem;
static nrf_rpc_os_mutex_t out_mutex;

static nrf_rpc_os_atomic_t free_mask[NUM_BLOCKS / WORD_BITS];

static nrf_rpc_tr_receive_handler_t receive_handler;

static inline void free_mask_set(mask_t mask)
{
	nrf_rpc_os_atomic_or(&free_mask[0], mask);
	if (NUM_BLOCKS > 32) {
		nrf_rpc_os_atomic_or(&free_mask[1], mask >> 32);
	}
	NRF_RPC_OS_MEMORY_BARIER();
}

static bool free_mask_unset(mask_t mask)
{
	uint32_t old;
	uint32_t mask_part;
	mask_part = (uint32_t)mask;
	old = nrf_rpc_os_atomic_and(&free_mask[0], ~mask_part);
	if ((old & mask_part) != mask_part) {
		nrf_rpc_os_atomic_or(&free_mask[0], old & mask_part);
		return false;
	}
	if (NUM_BLOCKS > 32) {
		mask_part = (uint32_t)(mask >> 32);
		old = nrf_rpc_os_atomic_and(&free_mask[1], ~mask_part);
		if ((old & mask_part) != mask_part) {
			nrf_rpc_os_atomic_or(&free_mask[1], old & mask_part);
			nrf_rpc_os_atomic_or(&free_mask[0], (uint32_t)mask);
			return false;
		}
	}
	NRF_RPC_OS_MEMORY_BARIER();
	return true;
}

static inline mask_t free_mask_get()
{
	mask_t mask;

	mask = nrf_rpc_os_atomic_get(&free_mask[0]);
	if (NUM_BLOCKS > 32) {
		mask = (mask_t)nrf_rpc_os_atomic_get(&free_mask[1]) << 32;
	}

	return mask;
}

static void free_mask_init()
{
	free_mask_set(~(mask_t)0);
}

static mask_t calc_mask(size_t blocks, size_t index)
{
	mask_t mask = (mask_t)1 << (NUM_BLOCKS - 1); // 100000000...
	mask = (smask_t)mask >> (blocks - 1);        // 111000000... (e.g. blocks = 3)
	mask = mask >> index;                        // 000011100... (e.g. index = 4)
	return mask;
}

void nrf_rpc_tr_alloc_tx_buf(uint8_t **buf, size_t len)
{
	size_t i;
	/* Actual allocated memory: | 32-bit size | data | padding | */
	size_t blocks = (len + (WORD_SIZE + OUT_BLOCK_SIZE - 1)) / OUT_BLOCK_SIZE;
	bool sem_taken = false;
	mask_t cur_mask;
	mask_t sh_mask;
	bool unset_success;
	mask_t mask;
	size_t free_index;

	if (blocks > NUM_BLOCKS || blocks == 0) {
		NRF_RPC_ERR("Requested %d bytes, maximum is %d", len, OUT_ALLOCABLE_SIZE - sizeof(uint32_t));
		NRF_RPC_ASSERT(0);
		nrf_rpc_os_fatal();
		*buf = NULL;
		return;
	}

	do {
		do {
			// create shifted mask with bits set where `blocks` can be allocated
			cur_mask = free_mask_get();
			sh_mask = cur_mask;
			for (i = 1; i < blocks; i++) {
				sh_mask &= (sh_mask << 1);
			}

			// if no memory
			if (sh_mask == 0) {
				// wait for any block to be empty
				nrf_rpc_os_take(&out_sem);
				sem_taken = true;
			}

		} while (sh_mask == 0);

		// get first available blocks
		free_index = mask_clz(sh_mask);
		// create bit mask with blocks that will be used
		mask = calc_mask(blocks, free_index);
		// update masks
		unset_success = free_mask_unset(mask);
		// there is a small probability that unset will be unsuccessful
		if (!unset_success) {
			// give semaphore, because free_mask_unset may cause other thread waiting before it reverted the changes
			nrf_rpc_os_give(&out_sem);
			sem_taken = false;
		}
	} while (!unset_success);

	// Give semaphore back, because there may be some other thread waiting
	if (sem_taken && (cur_mask & ~mask) != 0) {
		nrf_rpc_os_give(&out_sem);
	}

	uint32_t *mem_start = (uint32_t *)&out_allocable[OUT_BLOCK_SIZE * free_index];

	mem_start[0] = blocks * OUT_BLOCK_SIZE;

	*buf = (uint8_t *)(&mem_start[1]);
}

void nrf_rpc_tr_free_tx_buf(uint8_t *buf)
{
	uint32_t *mem_start = (uint32_t *)buf - 1;
	uint32_t offset = (uint8_t *)mem_start - out_allocable;
	uint32_t block_index = offset / OUT_BLOCK_SIZE;
	uint32_t allocated_size;
	uint32_t allocated_blocks;

	NRF_RPC_ASSERT(block_index < NUM_BLOCKS);
	NRF_RPC_ASSERT(buf == &out_allocable[block_index * OUT_BLOCK_SIZE]);

	allocated_size = mem_start[0];
	allocated_blocks = allocated_size / OUT_BLOCK_SIZE;

	NRF_RPC_ASSERT(allocated_blocks % OUT_BLOCK_SIZE == 0);
	NRF_RPC_ASSERT(allocated_size <= OUT_ALLOCABLE_SIZE);
	NRF_RPC_ASSERT(offset + allocated_size <= OUT_ALLOCABLE_SIZE);

	free_mask_set(calc_mask(allocated_blocks, block_index));
	nrf_rpc_os_give(&out_sem);
}


#define memory_corrupted_error() \
	NRF_RPC_ERR("Shared memory corrupted"); \
	NRF_RPC_ASSERT(0); \
	nrf_rpc_os_fatal();


static void queue_send(uint8_t data)
{
	uint32_t tx;
	uint32_t dst;

	nrf_rpc_os_lock(&out_mutex);

	tx = *out_queue_tx;
	dst = tx;

	if (dst >= OUT_QUEUE_ITEMS) {
		memory_corrupted_error();
		return;
	}

	tx++;
	if (tx >= OUT_QUEUE_ITEMS) {
		tx = 0;
	}

	out_queue[dst] = data;
	NRF_RPC_OS_MEMORY_BARIER();
	*out_queue_tx = tx;

	nrf_rpc_os_unlock(&out_mutex);

	nrf_rpc_os_signal();
}


int nrf_rpc_tr_send(uint8_t *buf, size_t len)
{
	uint32_t *mem_start = (uint32_t *)buf - 1;
	uint32_t offset = (uint8_t *)mem_start - out_allocable;
	uint32_t block_index = offset / OUT_BLOCK_SIZE;
	uint32_t allocated_size;
	uint32_t allocated_blocks;
	uint32_t blocks = (len + OUT_BLOCK_SIZE - 1) / OUT_BLOCK_SIZE;
	uint32_t total_len = len + WORD_SIZE;

	NRF_RPC_ASSERT(block_index < NUM_BLOCKS);
	NRF_RPC_ASSERT((uint8_t *)mem_start == &out_allocable[block_index * OUT_BLOCK_SIZE]);

	allocated_size = mem_start[0];
	allocated_blocks = allocated_size / OUT_BLOCK_SIZE;

	NRF_RPC_ASSERT(allocated_size % OUT_BLOCK_SIZE == 0);
	NRF_RPC_ASSERT(allocated_size <= OUT_ALLOCABLE_SIZE);
	NRF_RPC_ASSERT(offset + allocated_size <= OUT_ALLOCABLE_SIZE);
	NRF_RPC_ASSERT(total_len <= allocated_size);

	if (blocks < allocated_blocks) {
		free_mask_set(calc_mask(allocated_blocks - blocks, block_index + blocks));
		nrf_rpc_os_give(&out_sem);
	}

	mem_start[0] = total_len;

	queue_send(block_index);

	return 0;
}


static int queue_recv()
{
	uint32_t tx = *in_queue_tx;
	uint32_t rx = *in_queue_rx;
	uint8_t data;

	tx = *in_queue_tx;
	rx = *in_queue_rx;

	if (rx >= IN_QUEUE_ITEMS) {
		memory_corrupted_error();
		return -1;
	}

	if (tx == rx) {
		return -1;
	}

	NRF_RPC_OS_MEMORY_BARIER();

	data = in_queue[rx];

	rx++;
	if (rx >= IN_QUEUE_ITEMS) {
		rx = 0;
	}

	*in_queue_rx = rx;

	return data;
}


static void signal_received(void)
{
	int block;
	int release;
	uint32_t *mem_start;
	uint32_t total_size;
	uint32_t blocks;

	do {
		block = queue_recv();
		if (block < 0) {
			break;
		}

		release = (block & FLAG_RELEASE);
		block &= ~FLAG_RELEASE;

		if (block >= NUM_BLOCKS) {
			continue;
		}

		if (release) {
			mem_start = (uint32_t *)(&out_allocable[block * OUT_BLOCK_SIZE]);
			total_size = mem_start[0];
			blocks = (total_size + OUT_BLOCK_SIZE - 1) / OUT_BLOCK_SIZE;
			free_mask_set(calc_mask(blocks, block));
			nrf_rpc_os_give(&out_sem);
		} else {
			mem_start = (uint32_t *)(&in_allocable[block * IN_BLOCK_SIZE]);
			total_size = mem_start[0];
			if (total_size >= &in_allocable[IN_ALLOCABLE_SIZE] - (uint8_t *)mem_start || total_size < WORD_SIZE) {
				memory_corrupted_error();
				break;
			}
			receive_handler((uint8_t *)&mem_start[1], total_size - WORD_SIZE);
		}
	} while (true);
}

void nrf_rpc_tr_free_rx_buf(const uint8_t *packet)
{
	uint32_t *mem_start = (uint32_t *)packet - 1;
	uint32_t offset = (uint8_t *)mem_start - in_allocable;
	uint32_t block_index = offset / IN_BLOCK_SIZE;

	NRF_RPC_ASSERT(block_index < NUM_BLOCKS);

	queue_send(block_index | FLAG_RELEASE);
}

static void handshake_step(uint8_t this_value, uint8_t next_value)
{
	*out_handshake = this_value;
	NRF_RPC_OS_MEMORY_BARIER();
	while (*in_handshake != this_value && *in_handshake != next_value) {
		nrf_rpc_os_yield();
		NRF_RPC_OS_MEMORY_BARIER();
	}
}

int nrf_rpc_tr_init(nrf_rpc_tr_receive_handler_t callback)
{
	receive_handler = callback;

	free_mask_init();
	nrf_rpc_os_sem_init(&out_sem);
	nrf_rpc_os_mutex_init(&out_mutex);

#if !NRF_RPC_OS_SHMEM_PTR_CONST
	out_allocable = (uint8_t *)nrf_rpc_os_out_shmem_ptr;
	out_queue_tx = (uint32_t *)&out_allocable[OUT_ALLOCABLE_SIZE];
	out_queue_rx = (uint32_t *)&out_allocable[OUT_ALLOCABLE_SIZE + WORD_SIZE];
	out_queue = (uint8_t *)&out_allocable[OUT_ALLOCABLE_SIZE + 2 * WORD_SIZE];
	out_handshake = (uint8_t *)&out_allocable[OUT_TOTAL_SIZE - 1];
	in_allocable = (uint8_t *)nrf_rpc_os_in_shmem_ptr;
	in_queue_tx = (uint32_t *)&in_allocable[IN_ALLOCABLE_SIZE];
	in_queue_rx = (uint32_t *)&in_allocable[IN_ALLOCABLE_SIZE + WORD_SIZE];
	in_queue = (uint8_t *)&in_allocable[IN_ALLOCABLE_SIZE + 2 * WORD_SIZE];
	in_handshake = (uint8_t *)&in_allocable[IN_TOTAL_SIZE - 1];
#endif

	handshake_step(0x32, 0x43);
	handshake_step(0x43, 0xF6);

	*out_queue_tx = 0;
	*out_queue_rx = 0;
	*in_queue_tx = 0;
	*in_queue_rx = 0;
	
	nrf_rpc_os_signal_handler(signal_received);

	handshake_step(0xF6, 0xA8);
	handshake_step(0xA8, 0xA8);

	return 0;
}
