/*
    Yubico OTP implementation for the Ledger Nano S (nanos-app-yubico-otp)
    (c) 2017 Aleksejs Popovs <aleksejs@popovs.lv>

    including code based on
    Password Manager application
    (c) 2017 Ledger

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

#include <stdint.h>

#include "os.h"
#include "os_io_seproxyhal.h"

#include "usb_keyboard.h"

extern unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
static void io_usb_send_data(uint8_t endpoint, unsigned char *buffer,
                      unsigned short length) {
    unsigned int rx_len;

    // won't send if overflowing seproxyhal buffer format
    if (length > 255) {
        return;
    }

    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EP_PREPARE;
    G_io_seproxyhal_spi_buffer[1] = (3 + length) >> 8;
    G_io_seproxyhal_spi_buffer[2] = (3 + length);
    G_io_seproxyhal_spi_buffer[3] = 0x80 | endpoint;
    G_io_seproxyhal_spi_buffer[4] = SEPROXYHAL_TAG_USB_EP_PREPARE_DIR_IN;
    G_io_seproxyhal_spi_buffer[5] = length;
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 6);
    io_seproxyhal_spi_send(buffer, length);

    for (;;) {
        if (!io_seproxyhal_spi_is_status_sent()) {
            io_seproxyhal_general_status();
        }

        rx_len = io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                        sizeof(G_io_seproxyhal_spi_buffer), 0);

        // wait for ack of the seproxyhal
        // discard if not an acknowledgment
        if (G_io_seproxyhal_spi_buffer[0] != SEPROXYHAL_TAG_USB_EP_XFER_EVENT ||
            rx_len != 6 || G_io_seproxyhal_spi_buffer[3] != (0x80 | endpoint) ||
            G_io_seproxyhal_spi_buffer[4] != SEPROXYHAL_TAG_USB_EP_XFER_IN ||
            G_io_seproxyhal_spi_buffer[5] != length) {
            // usb reset ?
            io_seproxyhal_handle_usb_event();

            // link disconnected ?
            if (G_io_seproxyhal_spi_buffer[0] == SEPROXYHAL_TAG_STATUS_EVENT) {
                if (!(U4BE(G_io_seproxyhal_spi_buffer, 3) &
                      SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
                    THROW(EXCEPTION_IO_RESET);
                }
            }

            if (!io_event(CHANNEL_SPI)) {
                // THROW ??
            }

            if (!io_seproxyhal_spi_is_status_sent()) {
                io_seproxyhal_general_status();
            }

            // no general status ack, io_event is responsible for it
            continue;
        }

        // chunk sending succeeded
        break;
    }
}

#define KEYCODE_START 0x20
#define MAPPING_LENGTH 95

// these mapping are QWERTY-specific.
// for our purposes, that's mostly fine - modhex strings should still be
// entered correctly on AZERTY/QWERTZ/...
// sorry, DVORAK users!

// alt mask from ascii 0x20
// compressed into a bit mask: the value for i is stored in the
// (i%8)th bit of map[i/8]
static const uint8_t MAP_ALT[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// shift mask from ascii 0x20
// compressed into a bit mask: the value for i is stored in the
// (i%8)th bit of map[i/8]
static const uint8_t MAP_SHIFT[] = {
    0x7E, 0x0f, 0x00, 0xd4, 0xff, 0xff, 0xff, 0xc7, 0x00, 0x00, 0x00, 0x78};

// key codes from ascii 0x20
static const uint8_t MAP_KEY_CODE[] = {
    0x2c, 0x1e, 0x34, 0x20, 0x21, 0x22, 0x24, 0x34, 0x26, 0x27, 0x25, 0x2e,
    0x36, 0x2d, 0x37, 0x38, 0x27, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x33, 0x33, 0x36, 0x2e, 0x37, 0x38, 0x1f, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x2f,
    0x31, 0x30, 0x23, 0x2d, 0x35, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x2f, 0x31, 0x30, 0x35};

static const uint8_t EMPTY_REPORT[] = {0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00};

static void char_to_report(char key, uint8_t *out) {
    uint8_t bm_byte, bm_bit, key_code, alt_used, shift_used;

    if (key < KEYCODE_START) {
        THROW(EXCEPTION);
    }
    key -= KEYCODE_START;
    if (key > MAPPING_LENGTH) {
        THROW(EXCEPTION);
    }
    key_code = MAP_KEY_CODE[key];

    bm_byte = key >> 3;
    bm_bit = 1 << (key & 0x07);
    alt_used = ((MAP_ALT[bm_byte] & bm_bit) != 0);
    shift_used = ((MAP_SHIFT[bm_byte] & bm_bit) != 0);

    out[0] = (alt_used ? 0x40 : 0x00) | (shift_used ? 0x02 : 0x00);
    out[1] = 0x00;
    out[2] = key_code;
}

void usb_kbd_send_char(char ch) {
    uint8_t report[8] = {};
    char_to_report(ch, report);
    io_usb_send_data(1, report, 8);
    io_usb_send_data(1, EMPTY_REPORT, 8);
}

void usb_kbd_send_string(char* s) {
    uint8_t report[8] = {};
    for (; *s; s++) {
        char_to_report(*s, report);
        io_usb_send_data(1, report, 8);
        io_usb_send_data(1, EMPTY_REPORT, 8);
    }
}

void usb_kbd_send_enter() {
    uint8_t report[8] = {0, 0, 40};
    io_usb_send_data(1, report, 8);
    io_usb_send_data(1, EMPTY_REPORT, 8);
}
