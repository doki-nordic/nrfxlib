/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef NRF_RPC_SHMEM_H_
#define NRF_RPC_SHMEM_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* For API documentation see nrf_rpc_tr_tmpl.h */

#define NRF_RPC_TR_MAX_HEADER_SIZE 0
#define NRF_RPC_TR_AUTO_FREE_RX_BUF 0

typedef void (*nrf_rpc_tr_receive_handler_t)(const uint8_t *packet, size_t len);

int nrf_rpc_tr_init(nrf_rpc_tr_receive_handler_t callback);
void nrf_rpc_tr_free_rx_buf(const uint8_t *packet);
void nrf_rpc_tr_alloc_tx_buf(uint8_t **buf, size_t len);
void nrf_rpc_tr_free_tx_buf(uint8_t *buf);
int nrf_rpc_tr_send(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NRF_RPC_SHMEM_H_ */
