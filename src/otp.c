/*
    Yubico OTP implementation for the Ledger Nano S (nanos-app-yubico-otp)
    (c) 2017 Aleksejs Popovs <aleksejs@popovs.lv>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include "otp.h"

#include "os.h"
#include "cx.h"

#include "ctr_drbg.h"

static const char hex_alphabet[] = "0123456789abcdef";
void bytes_to_hex(uint8_t* bytes, uint32_t length, char* out) {
    uint32_t i;
    for (i = 0; i < length; i++) {
        out[2 * i]     = hex_alphabet[bytes[i] >> 4];
        out[2 * i + 1] = hex_alphabet[bytes[i] & 0xf];
    }
    out[2 * length] = 0;
}

static const char modhex_alphabet[] = "cbdefghijklnrtuv";
void bytes_to_modhex(uint8_t* bytes, uint32_t length, char* out) {
    uint32_t i;
    for (i = 0; i < length; i++) {
        out[2 * i]     = modhex_alphabet[bytes[i] >> 4];
        out[2 * i + 1] = modhex_alphabet[bytes[i] & 0xf];
    }
    out[2 * length] = 0;
}

static uint16_t crc_16(uint8_t *data, uint32_t length, uint16_t crc) {
    uint32_t i;
    for (i = 0; i < length; i++) {
        crc ^= data[i];
        uint8_t j;
        for (j = 0; j < 8; j++) {
            uint16_t n = crc & 1;
            crc >>= 1;
            if (n) {
                crc ^= 0x8408;
            }
        }
    }
    return crc;
}


// this has to be initialized separately (by calling otp_reset_token_counter()
// from main()) because initializing globals doesn't work well with the Ledger's
// architecture
uint8_t token_count_since_boot;

void otp_generate_token(otpKeySlot_t* key, char* token) {
    if (token_count_since_boot == 255) {
        THROW(EXCEPTION);
    }

    otpKeySecrets_t secrets;
    otp_derive_keys(key, &secrets);

    uint8_t plaintext[OTP_PRIVATE_ID_LEN + 2 + 3 + 1 + 4];
    // private ID
    os_memmove(&plaintext[0], secrets.private_id, OTP_PRIVATE_ID_LEN);
    // boot count, 2 bytes
    plaintext[OTP_PRIVATE_ID_LEN] = key->boot_count & 0xff;
    plaintext[OTP_PRIVATE_ID_LEN + 1] = key->boot_count >> 8;
    // time stamp, 3 bytes
    // the ledger doesn't really have an RTC, so for now we just use the counter
    // to get something monotonically increasing.
    // when validating, timestamps are only used for phishing attack detection,
    // which isn't even really properly implemented in the official validator
    // anyway.
    plaintext[OTP_PRIVATE_ID_LEN + 2] = token_count_since_boot;
    plaintext[OTP_PRIVATE_ID_LEN + 2 + 1] = 0;
    plaintext[OTP_PRIVATE_ID_LEN + 2 + 2] = 0;
    // counter, 1 byte
    plaintext[OTP_PRIVATE_ID_LEN + 5] = token_count_since_boot;
    // junk, 4 bytes
    // we insert two random bytes, then bruteforce the other two to get the correct CRC16
    plaintext[OTP_PRIVATE_ID_LEN + 6] = cx_rng_u8();
    plaintext[OTP_PRIVATE_ID_LEN + 6 + 1] = cx_rng_u8();

    uint16_t partial_crc = crc_16(plaintext, OTP_PRIVATE_ID_LEN + 2 + 3 + 1 + 2, 0xffff);
    uint8_t junk[2];
    uint8_t done = 0;
    // TODO optimize
    for (junk[0] = 0; ++junk[0] != 0;) {
        for (junk[1] = 0; ++junk[1] != 0;) {
            if (crc_16(junk, 2, partial_crc) == 0xf0b8) {
                done = 1;
                break;
            }
        }

        if (done) {
            break;
        }
    }

    plaintext[OTP_PRIVATE_ID_LEN + 6 + 2] = junk[0];
    plaintext[OTP_PRIVATE_ID_LEN + 6 + 3] = junk[1];

    cx_aes_key_t aes_key;
    cx_aes_init_key(secrets.aes_key, OTP_AES_KEY_LEN, &aes_key);
    uint8_t token_bytes[OTP_PRIVATE_ID_LEN + 2 + 3 + 1 + 4];
    cx_aes(&aes_key, CX_ENCRYPT | CX_PAD_NONE | CX_CHAIN_ECB,
        plaintext, OTP_PRIVATE_ID_LEN + 2 + 3 + 1 + 4,
        token_bytes);

    otp_print_public_id(key, &token[0]);
    bytes_to_modhex(token_bytes, OTP_PRIVATE_ID_LEN + 2 + 3 + 1 + 4,
        &token[OTP_PUBLIC_ID_PRINTABLE_LEN]);

    token_count_since_boot++;
}

void otp_print_public_id(otpKeySlot_t* key, char* public_id) {
    bytes_to_modhex(key->public_id, OTP_PUBLIC_ID_LEN, public_id);
}

void otp_initialize_key(otpKeySlot_t* key) {
    key->enabled = 1;
    key->boot_count = 1;
    cx_rng(key->public_id, OTP_PUBLIC_ID_LEN);
}

static uint8_t entropy_provided;
static uint8_t entropy[32];

static int entropy_provider(void *context, unsigned char *buffer, size_t bufferSize) {
    if (entropy_provided) {
        return 1;
    }
    if (bufferSize != 32) {
        return 1;
    }
    os_memmove(buffer, entropy, 32);
    entropy_provided = 1;
    return 0;
}

void otp_derive_keys(otpKeySlot_t* key, otpKeySecrets_t* secrets) {
    uint32_t derive[9];
    uint8_t tmp[64];
    uint8_t i;
    cx_hash_sha256(key->public_id, OTP_PUBLIC_ID_LEN, tmp);
    derive[0] = OTP_DERIVATION_PATH;
    for (i = 0; i < 8; i++) {
        derive[i + 1] = (tmp[4 * i] << 24) | (tmp[4 * i + 1] << 16) |
                        (tmp[4 * i + 2] << 8) | (tmp[4 * i + 3]);
        derive[i + 1] |= 0x80000000;
    }
    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, derive, 9, tmp, tmp + 32);
    cx_hash_sha256(tmp, 64, entropy);
    os_memset(tmp, 0, sizeof(tmp));
    entropy_provided = 0;
    mbedtls_ctr_drbg_context ctx;
    mbedtls_ctr_drbg_init(&ctx);
    if (mbedtls_ctr_drbg_seed(&ctx, entropy_provider, NULL, NULL, 0) != 0) {
        THROW(EXCEPTION);
    }

    mbedtls_ctr_drbg_random(&ctx, secrets->aes_key, OTP_AES_KEY_LEN);
    mbedtls_ctr_drbg_random(&ctx, secrets->private_id, OTP_PRIVATE_ID_LEN);
}

void otp_print_private_id(otpKeySecrets_t* secrets, char* private_id) {
    bytes_to_hex(secrets->private_id, OTP_PRIVATE_ID_LEN, private_id);
}

void otp_print_aes_key(otpKeySecrets_t* secrets, char* key1, char* key2, char* key3) {
    bytes_to_hex(&secrets->aes_key[0], 5, key1);
    bytes_to_hex(&secrets->aes_key[5], 5, key2);
    bytes_to_hex(&secrets->aes_key[10], 6, key3);
}

void otp_reset_token_counter() {
    token_count_since_boot = 0;
}
