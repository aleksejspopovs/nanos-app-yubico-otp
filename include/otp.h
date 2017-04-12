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

#ifndef OTP_H

#define OTP_H

#include <stdint.h>

#define OTP_DERIVATION_PATH 0x79756269 // 'yubi' in hex

#define OTP_AES_KEY_LEN 16
#define OTP_PUBLIC_ID_LEN 6
#define OTP_PRIVATE_ID_LEN 6

#define OTP_PUBLIC_ID_PRINTABLE_LEN 12
#define OTP_PRIVATE_ID_PRINTABLE_LEN 12
#define OTP_AES_KEY_PRINTABLE_MAX_LEN 12
#define OTP_TOKEN_LEN 44

typedef struct otpKeySlot_t {
    uint8_t enabled;
    uint8_t public_id[OTP_PUBLIC_ID_LEN];
    uint16_t boot_count;
} otpKeySlot_t;

typedef struct otpKeySecrets_t {
    uint8_t aes_key[OTP_AES_KEY_LEN];
    uint8_t private_id[OTP_PRIVATE_ID_LEN];
} otpKeySecrets_t;

void bytes_to_hex(uint8_t* bytes, uint32_t length, char* out);

void bytes_to_modhex(uint8_t* bytes, uint32_t length, char* out);


void otp_generate_token(otpKeySlot_t* key, char* token);

void otp_print_public_id(otpKeySlot_t* key, char* public_id);

void otp_initialize_key(otpKeySlot_t* key);

void otp_derive_keys(otpKeySlot_t* key, otpKeySecrets_t* secrets);

void otp_print_private_id(otpKeySecrets_t* secrets, char* private_id);

void otp_print_aes_key(otpKeySecrets_t* secrets, char* key1, char* key2, char* key3);

void otp_reset_token_counter();

#endif
