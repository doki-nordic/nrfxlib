/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef NRF_RPC_OS_H_
#define NRF_RPC_OS_H_

/*
 * THIS IS A TEMPLATE FILE.
 * It should be copied to a suitable location within the host environment into
 * which Remote Procedure serialization is integrated, and the following macros
 * should be provided with appropriate implementations.
 */

/**
 * @defgroup nrf_rpc_os OS-dependent functionality for nRF PRC
 * @{
 * @ingroup nrf_rpc
 *
 * @brief OS-dependent functionality for nRF PRC
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Structure to pass events between threads. */
struct nrf_rpc_os_event;

/** @brief Structure to pass messages between threads. */
struct nrf_rpc_os_msg;

/** @brief Work callback that will be called from thread pool.
 *
 * @param data Data passed from @ref nrf_rpc_os_thread_pool_send.
 * @param len  Data length.
 */
typedef void (*nrf_rpc_os_work_t)(const uint8_t *data, size_t len);

/** @brief nRF RPC OS-dependent initialization.
 *
 * @param callback Work callback that will be called when something was send
 *                 to a thread pool.
 *
 * @return         0 on success or negative error code.
 */
int nrf_rpc_os_init(nrf_rpc_os_work_t callback);

/** @brief Send work to a thread pool.
 *
 * Function reserves a thread from a thread pool and executes callback provided
 * in @ref nrf_rpc_os_init with `data` and `len` paramteres. If there is no
 * thread available in the thread pool then this function waits.
 *
 * @param data Data pointer to pass. Data is passed as a pointer, no copying is
 *             done.
 * @param len  Length of the `data`.
 */
void nrf_rpc_os_thread_pool_send(const uint8_t *data, size_t len);

/** @brief Initialize event passing structure.
 *
 * @param event Event structure to initialize.
 *
 * @return      0 on success or negative error code.
 */
int nrf_rpc_os_event_init(struct nrf_rpc_os_event *event);

/** @brief Set an event.
 *
 * If some thread is waiting of the event then it will be waken up. If there is
 * no thread waiting next call to @ref nrf_rpc_os_event_wait will return
 * immediately.
 *
 * Event behavior is the same as a binary semaphore.
 *
 * @param event Event to set.
 */
void nrf_rpc_os_event_set(struct nrf_rpc_os_event *event);

/** @brief Wait for an event.
 *
 * @param event Event to wait for.
 */
void nrf_rpc_os_event_wait(struct nrf_rpc_os_event *event);

/** @brief Initialize message passing structure.
 *
 * @param msg Structure to initialize.
 *
 * @return    0 on success or negative error code.
 */
int nrf_rpc_os_msg_init(struct nrf_rpc_os_msg *msg);

/** @brief Pass a message to a different therad.
 *
 * nRF RPC is passing one message at a time, so there is no need to do
 * FIFO here.
 *
 * @param msg  Message passing structure.
 * @param data Data pointer to pass. Data is passed as a pointer, so no copying
 *             is done.
 * @param len  Length of the `data`.
 */
void nrf_rpc_os_msg_set(struct nrf_rpc_os_msg *msg, const uint8_t *data,
			size_t len);

/** @brief Get a message.
 *
 * If message was not set yet then this function waits.
 *
 * @param[in]  msg  Message passing structure.
 * @param[out] data Received data pointer. Data is passed as a pointer, so no
 *                  copying is done.
 * @param[out] len  Length of the `data`.
 */
void nrf_rpc_os_msg_get(struct nrf_rpc_os_msg *msg, const uint8_t **data,
			size_t *len);

/** @brief Get TLS (Thread Local Storage) for nRF RPC.
 *
 * nRF PRC need one pointer to associate with a thread.
 *
 * @return Pointer stored on TLS or NULL if pointer was not set for this thread.
 */
void* nrf_rpc_os_tls_get(void);

/** @brief Set TLS (Thread Local Storage) for nRF RPC.
 *
 * @param data Pointer to store on TLS.
 */
void nrf_rpc_os_tls_set(void *data);

/** @brief Reserve one context from command context pool.
 *
 * If there is no available context then this function waits for it.
 *
 * @return Context index between 0 and
 *         @option{CONFIG_NRF_RPC_CMD_CTX_POOL_SIZE} - 1.
 */
uint32_t nrf_rpc_os_ctx_pool_reserve();

/** @brief Release context from context pool.
 *
 * @param index Context index that was previously reserved.
 */
void nrf_rpc_os_ctx_pool_release(uint32_t index);

/** @brief Set number of remote threads.
 *
 * Number of remote threads that can be reserved by
 * @ref nrf_rpc_os_remote_reserve is limited by `count` parameter.
 * After initialization `count` is assumed to be zero.
 *
 * @param count Number of remote threads.
 */
void nrf_rpc_os_remote_count(int count);

/** @brief Reserve one thread from a remote thread pool.
 *
 * If there are no more threads available or @ref nrf_rpc_os_remote_count was
 * not called yet then this function waits.
 *
 * Remote thread reserving and releasing can be implemented using a semaphore.
 */
void nrf_rpc_os_remote_reserve();

/** @brief Release one thread from a remote thread pool.
 */
void nrf_rpc_os_remote_release();

/* Below OS-dependent API is only needed if shared memory transport is used.
 */
#ifdef CONFIG_NRF_RPC_TR_SHMEM

/* --------------- Shared memory information --------------- */

/** @brief Defines whether shared memory pointers are contant
 * (known on build time).
 *
 * If defined as `1` @ref nrf_rpc_os_out_shmem_ptr and
 * @ref nrf_rpc_os_in_shmem_ptr are constant defines.
 *
 * If defined as `0` @ref nrf_rpc_os_out_shmem_ptr and
 * @ref nrf_rpc_os_in_shmem_ptr are not constant and must be set
 * before exit from @ref nrf_rpc_os_init.
 */
#define NRF_RPC_OS_SHMEM_PTR_CONST 0

/** @brief Poiter to shared memory that will be used for output.
 */
extern void *nrf_rpc_os_out_shmem_ptr;

/** @brief Poiter to shared memory that will be used for input.
 */
extern void *nrf_rpc_os_in_shmem_ptr;

/** @brief Full memory barier.
 */
#define NRF_RPC_OS_MEMORY_BARIER() __sync_synchronize()

/* --------------- Inter-core signaling --------------- */

/** @brief Signal other core that new data is waiting.
 */
void nrf_rpc_os_signal(void);

/** @brief Sets callback that will be called when the other core
 *  has signaled incoming data.
 */
void nrf_rpc_os_signal_handler(void (*handler)(void));

/* --------------- Atomics --------------- */

typedef some_type nrf_rpc_os_atomic_t;

/* Perform the operation suggested by the name, and return the value that
 * had previously been in *atomic.
 */
uint32_t nrf_rpc_os_atomic_or(nrf_rpc_os_atomic_t *atomic, uint32_t value);
uint32_t nrf_rpc_os_atomic_and(nrf_rpc_os_atomic_t *atomic, uint32_t value);
uint32_t nrf_rpc_os_atomic_get(nrf_rpc_os_atomic_t *atomic);

/* --------------- Mutexes --------------- */

typedef some_type nrf_rpc_os_mutex_t;
void nrf_rpc_os_mutex_init(nrf_rpc_os_mutex_t *mutex);
void nrf_rpc_os_lock(pthread_mutex_t *mutex);
void nrf_rpc_os_unlock(pthread_mutex_t *mutex);

/* --------------- Semaphores --------------- */

typedef some_type nrf_rpc_os_sem_t;
void nrf_rpc_os_sem_init(nrf_rpc_os_sem_t *sem);
void nrf_rpc_os_take(nrf_rpc_os_sem_t *sem);
void nrf_rpc_os_give(nrf_rpc_os_sem_t *sem);

/* --------------- Other OS functionality --------------- */

void nrf_rpc_os_yield();
void nrf_rpc_os_fatal(void);
int nrf_rpc_os_clz64(uint64_t value);
int nrf_rpc_os_clz32(uint32_t value);

#endif /* CONFIG_NRF_RPC_TR_SHMEM */

#ifdef __cplusplus
}
#endif

/**
 *@}
 */

#endif /* NRF_RPC_OS_H_ */
