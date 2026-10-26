/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LORA_APP_H
#define LORA_APP_H
#include "security_protocol.h"
int secure_lora_main(uint8_t role, const struct proto_identity *identity);
#endif
