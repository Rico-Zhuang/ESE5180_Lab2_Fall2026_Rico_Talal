/* SPDX-License-Identifier: Apache-2.0 */
#include "lora_app.h"
#include "identity.h" /* Generated locally by tools/provision.py. */

int main(void)
{
    return secure_lora_main(PROTO_CLIENT, &board_identity);
}
