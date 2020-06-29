/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _NRF_RPC_CBOR_H_
#define _NRF_RPC_CBOR_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <tinycbor/cbor.h>
#include <tinycbor/cbor_buf_writer.h>
#include <tinycbor/cbor_buf_reader.h>

#include <nrf_rpc.h>

/**
 * @defgroup nrf_rpc_cbor TinyCBOR serialization layer for nRF RPC.
 * @{
 * @ingroup nrf_rpc
 *
 * @brief Module simplifying usage of TinyCBOR as a serialization for nRF RPC
 * module.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Callback that handles decoding of commands, events and responses.
 *
 * @param value        TinyCBOR value to decode.
 * @param handler_data Custom handler data.
 */
typedef void (*nrf_rpc_cbor_handler_t)(CborValue *value, void *handler_data);

/* Structure used internally to define TinCBOR command or event decoder. */
struct _nrf_rpc_cbor_decoder {
	nrf_rpc_cbor_handler_t handler;
	void *handler_data;
	bool decoding_done_required;
};

/** @brief Context for encoding and sending commands, events and responses.
 *
 * Initialize it with @ref NRF_RPC_CBOR_ALLOC macro. Only `encoder` field is
 * significant for the API, other fields are internal.
 */
struct nrf_rpc_cbor_ctx {
	/** @brief TinyCBOR encoder. */
	CborEncoder encoder;
	struct cbor_buf_writer writer;
	uint8_t *out_packet;
};

/** @brief Context for encoding commands, sending commands, receiving responses
 * and parsing them.
 *
 * Initialize it with @ref NRF_RPC_CBOR_ALLOC macro. Only `encoder` and `value`
 * fields are significant for the API, other fields are internal.
 */
struct nrf_rpc_cbor_rsp_ctx {
	union {
		struct {
			/** @brief TinyCBOR encoder for encoding command. */
			CborEncoder encoder;
			struct cbor_buf_writer writer;
			uint8_t *out_packet;
		};
		struct {
			/** @brief TinyCBOR value for parsing response. */
			CborValue value;
			CborParser parser;
			struct cbor_buf_reader reader;
			const uint8_t *in_packet;
		};
	};
};

/** @brief Register a command decoder.
 *
 * @param _group   Group that the decoder will belong to, created with a
 *                 @ref NRF_RPC_GROUP_DEFINE().
 * @param _name    Name of the decoder.
 * @param _cmd     Command id. Can be from 0 to 254.
 * @param _handler Handler function of type @ref nrf_rpc_cbor_handler_t.
 * @param _data    Opaque pointer for the `_handler`.
 */
#define NRF_RPC_CBOR_CMD_DECODER(_group, _name, _cmd, _handler, _data)	       \
	static const							       \
	struct _nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {     \
		.handler = _handler,					       \
		.handler_data = _data,					       \
		.decoding_done_required = true,				       \
	};								       \
	NRF_RPC_CMD_DECODER(_group, _name, _cmd, _nrf_rpc_cbor_proxy_handler,  \
			    (void *)&NRF_RPC_CONCAT(_name, _cbor_data))

/** @brief Register an event decoder.
 *
 * @param _group   Group that the decoder will belong to, created with a
 *                 @ref NRF_RPC_GROUP_DEFINE().
 * @param _name    Name of the decoder.
 * @param _evt     Event id. Can be from 0 to 254.
 * @param _handler Handler function of type @ref nrf_rpc_cbor_handler_t.
 * @param _data    Opaque pointer for the `_handler`.
 */
#define NRF_RPC_CBOR_EVT_DECODER(_group, _name, _evt, _handler, _data)	       \
	static const							       \
	struct _nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {     \
		.handler = _handler,					       \
		.handler_data = _data,					       \
		.decoding_done_required = true,				       \
	};								       \
	NRF_RPC_EVT_DECODER(_group, _name, _evt, _nrf_rpc_cbor_proxy_handler,  \
			    (void *)&NRF_RPC_CONCAT(_name, _cbor_data))

/** @brief Allocates memory for a packet.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 *
 * Memory is automatically deallocated when it is passed to any of the send
 * functions. If not @ref NRF_RPC_CBOR_DISCARD() can be used.
 *
 * @param[out] _ctx  Variable of type @ref nrf_rpc_cbor_ctx or
 *                   @ref nrf_rpc_cbor_rsp_ctx that will hold newly allocated
 *                   resources to encode and send a packet.
 * @param[in]  _len  Requested length of the packet.
 */
#ifdef nrf_rpc_tr_alloc_tx_buf
#define NRF_RPC_CBOR_ALLOC(_ctx, _len)					       \
	NRF_RPC_ALLOC((_ctx).out_packet, (_len) + 1);			       \
	_nrf_rpc_cbor_prepare((struct nrf_rpc_cbor_ctx *)(&(_ctx)), (_len) + 1)
#else
#define NRF_RPC_ALLOC(_packet, _len)					       \
	_nrf_rpc_cbor_prepare((struct nrf_rpc_cbor_ctx *)(&(_ctx)), (_len) + 1)
#endif

/** @brief Deallocate memory for a packet.
 *
 * This macro should be used if memory was allocated, but it will not be sent
 * with any of the send functions.
 *
 * @param _ctx Packet that was previously allocated.
 */
#define NRF_RPC_CBOR_DISCARD(_ctx) NRF_RPC_DISCARD((_ctx).out_packet)

/** @brief Send a command and provide callback to handle response.
 *
 * @param group        Group that command belongs to.
 * @param cmd          Command id.
 * @param ctx          Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 * @param handler      Callback that handles the response. In case of error
 *                     (e.g. malformed response packet was received) it is
 *                     undefined if the handler will be called.
 * @param handler_data Opaque pointer that will be passed to `handler`.
 *
 * @return             0 on success or negative error code if a transport layer
 *                     reported a sendig error.
 */
int nrf_rpc_cbor_cmd(const struct nrf_rpc_group *group, uint8_t cmd,
		     struct nrf_rpc_cbor_ctx *ctx,
		     nrf_rpc_cbor_handler_t handler, void *handler_data);

/** @brief Send a command and get response as an output parameter.
 *
 * This variant of command send function outputs response as an output
 * parameter. Caller is responsible to call @ref nrf_rpc_cbor_decoding_done
 * just after response packet was decoded and can be deallocated.
 * `ctx->value` can be used to decode the response.
 *
 * @param group  Group that command belongs to.
 * @param cmd    Command id.
 * @param ctx    Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 *
 * @return       0 on success or negative error code if a transport
 *               layer reported a sendig error.
 */
int nrf_rpc_cbor_cmd_rsp(const struct nrf_rpc_group *group, uint8_t cmd,
			 struct nrf_rpc_cbor_rsp_ctx *ctx);

/** @brief Send a command, provide callback to handle response and pass any
 * error to an error handler.
 *
 * This variant of command send function returns `void`, so sending error
 * returned from the transport layer is passed to the error handler.
 * Source of error is @ref NRF_RPC_ERR_SRC_SEND.
 *
 * @param group        Group that command belongs to.
 * @param cmd          Command id.
 * @param ctx          Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 * @param handler      Callback that handles the response. In case of error
 *                     (e.g. malformed response packet was received) it is
 *                     undefined if the handler will be called.
 * @param handler_data Opaque pointer that will be passed to `handler`.
 */
void nrf_rpc_cbor_cmd_no_err(const struct nrf_rpc_group *group, uint8_t cmd,
			     struct nrf_rpc_cbor_ctx *ctx,
			     nrf_rpc_cbor_handler_t handler,
			     void *handler_data);

/** @brief Send a command, get response as an output parameter and pass any
 * error to an error handler.
 *
 * See both @ref nrf_rpc_cbor_cmd_rsp and @ref nrf_rpc_cbor_cmd_no_err for more
 * details on this variant of command send function.
 *
 * TinyCBOR value will be initialized and invalid if function failed, so
 * `cbor_value_is_valid` can be used to check failure.
 *
 * @param group  Group that command belongs to.
 * @param cmd    Command id.
 * @param ctx    Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 */
void nrf_rpc_cbor_cmd_rsp_no_err(const struct nrf_rpc_group *group,
				 uint8_t cmd, struct nrf_rpc_cbor_rsp_ctx *ctx);

/** @brief Send an event.
 *
 * @param group  Group that event belongs to.
 * @param evt    Event id.
 * @param ctx    Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 *
 * @return       0 on success or negative error code if a transport layer
 *               reported a sendig error.
 */
int nrf_rpc_cbor_evt(const struct nrf_rpc_group *group, uint8_t evt,
		     struct nrf_rpc_cbor_ctx *ctx);

/** @brief Send an event and pass any error to an error handler.
 *
 * This variant of event send function returns `void`, so sending error
 * returned from the transport layer is passed to the error handler.
 * Source of error is @ref NRF_RPC_ERR_SRC_SEND.
 *
 * @param group  Group that event belongs to.
 * @param evt    Event id.
 * @param ctx    Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 */
void nrf_rpc_cbor_evt_no_err(const struct nrf_rpc_group *group, uint8_t evt,
			     struct nrf_rpc_cbor_ctx *ctx);

/** @brief Send a response.
 *
 * @param ctx    Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 *
 * @return       0 on success or negative error code if a transport layer
 *               reported a sendig error.
 */
int nrf_rpc_cbor_rsp(struct nrf_rpc_cbor_ctx *ctx);

/** @brief Send a response and pass any error to an error handler.
 *
 * This variant of response send function returns `void`, so sending error
 * returned from the transport layer is passed to the error handler.
 * Source of error is @ref NRF_RPC_ERR_SRC_SEND.
 *
 * @param ctx    Context allocated by @ref NRF_RPC_CBOR_ALLOC.
 */
void nrf_rpc_cbor_rsp_no_err(struct nrf_rpc_cbor_ctx *ctx);

/** @brief Indicate that decoding of the input packet is done.
 *
 * This function must be called as soon as the input packet was parsed and can
 * be deallocated. It must be called in command decoder, event decoder and after
 * @ref nrf_rpc_cbor_cmd_rsp or @ref nrf_rpc_cbor_cmd_rsp_no_err. Packet is
 * automatically deallocated after completetion of the response handler
 * function, so this `nrf_rpc_cbor_decoding_done` is not needed in response
 * handler.
 */
void nrf_rpc_cbor_decoding_done(CborValue *value);

/* Functions used internally by the macros, not intended to be used directly. */
void _nrf_rpc_cbor_prepare(struct nrf_rpc_cbor_ctx *ctx, size_t len);
void _nrf_rpc_cbor_proxy_handler(const uint8_t *packet, size_t len,
				 void *handler_data);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _NRF_RPC_CBOR_H_ */
