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

#include "os.h"
#include "cx.h"
#include <stdbool.h>

#include "os_io_seproxyhal.h"
#include "string.h"

#include "glyphs.h"

#include "usb_keyboard.h"
#include "otp.h"


#if TARGET_ID != 0x31100002
#error Only Ledger Nano S (target 0x31100002) is supported at the time.
#endif

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#define CLA 0xE0

enum {
    MODE_NONE,
    MODE_CREATE,
    MODE_TYPE,
    MODE_REMOVE,
};
uint8_t mode;

typedef struct internalStorage_t {
#define STORAGE_MAGIC 0x0420EC41
    uint32_t magic;
    otpKeySlot_t keyslots[MAX_OTP_KEYSLOTS];
} internalStorage_t;

WIDE internalStorage_t N_storage_real;
#define N_storage (*(WIDE internalStorage_t *)PIC(&N_storage_real))

void type_otp(otpKeySlot_t* key) {
    char otp[OTP_TOKEN_LEN + 1];
    otp_generate_token(key, otp);
    usb_kbd_send_string(otp);
    usb_kbd_send_enter();
}

void reset_keyslots(void) {
    nvm_write(N_storage.keyslots, NULL, sizeof(N_storage.keyslots));
}

void increment_bootcounts(void) {
    uint32_t i;
    for (i = 0; i < MAX_OTP_KEYSLOTS; i++) {
        if (N_storage.keyslots[i].enabled) {
            uint16_t new_boot_count = N_storage.keyslots[i].boot_count + 1;
            nvm_write(&N_storage.keyslots[i].boot_count,
                &new_boot_count, sizeof(uint16_t));
        }
    }
}

void erase_keyslot(uint32_t which) {
    nvm_write(&N_storage.keyslots[which], NULL, sizeof(N_storage.keyslots[0]));

    uint32_t i;
    uint32_t overwrite = which;
    for (i = which + 1; i < MAX_OTP_KEYSLOTS; i++) {
        if (N_storage.keyslots[i].enabled) {
            nvm_write(&N_storage.keyslots[overwrite],
                &N_storage.keyslots[i],
                sizeof(N_storage.keyslots[0]));
            overwrite++;
            nvm_write(&N_storage.keyslots[i], NULL, sizeof(N_storage.keyslots[0]));
        }
    }
}

uint32_t find_free_keyslot(void) {
    uint32_t i;
    for (i = 0; i < MAX_OTP_KEYSLOTS; i++) {
        if (!N_storage.keyslots[i].enabled)
            return i;
    }
    return -1UL;
}

uint8_t add_keyslot(otpKeySlot_t* keyslot) {
    uint32_t where = find_free_keyslot();
    if (where == -1UL) {
        return 0;
    }
    nvm_write(&N_storage.keyslots[where], keyslot, sizeof(otpKeySlot_t));
    return 1;
}

ux_state_t ux;
const ux_menu_entry_t menu_main[];
void menu_list_init(unsigned int new_mode);

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Yubico OTP", "for Nano S", 0, 0},
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {menu_main, NULL, 4, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

void menu_reset_confirm(unsigned int ignored) {
    UNUSED(ignored);
    reset_keyslots();
    UX_MENU_DISPLAY(3, menu_main, NULL);
}

const ux_menu_entry_t menu_reset_all[] = {
    {menu_main, NULL, 3, NULL, "No", NULL, 0, 0},
    {NULL, menu_reset_confirm, 0, NULL, "Yes", NULL, 0, 0},
    UX_MENU_END};

void menu_entry_type_otp(unsigned int which) {
    type_otp(&N_storage.keyslots[which]);
}

uint32_t removed_entry;
void menu_entry_reset_confirm(unsigned int ignored) {
    UNUSED(ignored);
    erase_keyslot(removed_entry);
    // redisplay the complete remove menu
    menu_list_init(MODE_REMOVE);
}

void menu_entry_reset_cancel(unsigned int ignored) {
    UNUSED(ignored);
    // redisplay the complete remove menu
    menu_list_init(MODE_REMOVE);
}

const ux_menu_entry_t menu_entry_reset[] = {
    {NULL, menu_entry_reset_cancel, 0, NULL, "No", NULL, 0, 0},
    {NULL, menu_entry_reset_confirm, 0, NULL, "Yes", NULL, 0, 0},
    UX_MENU_END};

void menu_entry_remove(unsigned int which) {
    removed_entry = which;
    UX_MENU_DISPLAY(0, menu_entry_reset, NULL);
}

char public_id[OTP_PUBLIC_ID_PRINTABLE_LEN + 1];
char public_id_prev[OTP_PUBLIC_ID_PRINTABLE_LEN + 1];
char public_id_next[OTP_PUBLIC_ID_PRINTABLE_LEN + 1];
const ux_menu_entry_t menu_entries_default[] = {
    {NULL, NULL, 0, NULL, public_id_prev, NULL, 0, 0},
    {NULL, menu_entry_type_otp, 0, NULL, public_id, NULL, 0, 0},
    {NULL, NULL, 0, NULL, public_id_next, NULL, 0, 0},
    {menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
};
ux_menu_entry_t fake_entries[4];

const ux_menu_entry_t *menu_entries_iterator(unsigned int entry_index) {
    // the last entry is "back"
    if (entry_index == ux_menu.menu_entries_count - 1) {
        os_memmove(&fake_entries[3], &menu_entries_default[3],
                   sizeof(ux_menu_entry_t));
        // return to appropriate entry of main menu
        switch (mode) {
        case MODE_TYPE:
            fake_entries[3].userid = 0;
            break;
        case MODE_REMOVE:
            fake_entries[3].userid = 2;
            break;
        }
        return &fake_entries[3];
    }

    if (ux_menu.current_entry > entry_index) {
        // get previous
        // not called if no previous element
        os_memmove(&fake_entries[0], &menu_entries_default[0],
                   sizeof(ux_menu_entry_t));
        otp_print_public_id(&N_storage.keyslots[entry_index], public_id_prev);
        return &fake_entries[0];
    } else if (ux_menu.current_entry == entry_index) {
        // get current
        os_memmove(&fake_entries[1], &menu_entries_default[1],
                   sizeof(ux_menu_entry_t));
        otp_print_public_id(&N_storage.keyslots[entry_index], public_id);
        switch (mode) {
        case MODE_TYPE:
            fake_entries[1].callback = &menu_entry_type_otp;
            break;
        case MODE_REMOVE:
            fake_entries[1].callback = &menu_entry_remove;
            break;
        }
        fake_entries[1].userid = entry_index;
        return &fake_entries[1];
    } else { // ux_menu.current_entry < entry_index
        // get next
        // not called if no next element
        os_memmove(&fake_entries[2], &menu_entries_default[2],
                   sizeof(ux_menu_entry_t));
        otp_print_public_id(&N_storage.keyslots[entry_index], public_id_next);
        return &fake_entries[2];
    }
}

void menu_list_init(unsigned int new_mode) {
    UX_MENU_DISPLAY(0, NULL, NULL);
    // count number of entries
    ux_menu.menu_entries_count = 0;
    uint32_t i;
    for (i = 0; i < MAX_OTP_KEYSLOTS; i++) {
        if (N_storage.keyslots[i].enabled)
            ux_menu.menu_entries_count++;
    }
    // the back item
    ux_menu.menu_entries_count++;
    // setup iterator
    ux_menu.menu_iterator = menu_entries_iterator;
    mode = new_mode;
}

const ux_menu_entry_t menu_out_of_keyslots[] = {
    {NULL, NULL, 0, NULL, "Error", "Too many keys", 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

char new_key_public_id[OTP_PUBLIC_ID_PRINTABLE_LEN + 1];
char new_key_private_id[OTP_PRIVATE_ID_PRINTABLE_LEN + 1];
char new_key_aes_1[OTP_AES_KEY_PRINTABLE_MAX_LEN + 1];
char new_key_aes_2[OTP_AES_KEY_PRINTABLE_MAX_LEN + 1];
char new_key_aes_3[OTP_AES_KEY_PRINTABLE_MAX_LEN + 1];
const ux_menu_entry_t menu_new_key[] = {
    {NULL, NULL, 0, NULL, "Public ID", new_key_public_id, 0, 0},
    {NULL, NULL, 0, NULL, "Private ID", new_key_private_id, 0, 0},
    {NULL, NULL, 0, NULL, "AES key (1/3)", new_key_aes_1, 0, 0},
    {NULL, NULL, 0, NULL, "AES key (2/3)", new_key_aes_2, 0, 0},
    {NULL, NULL, 0, NULL, "AES key (3/3)", new_key_aes_3, 0, 0},
    {menu_main, NULL, 0, &C_icon_back, "Done", NULL, 61, 40},
    UX_MENU_END};

void menu_new_entry(unsigned int userid) {
    UNUSED(userid);

    if (find_free_keyslot() == -1UL) {
        UX_MENU_DISPLAY(0, menu_out_of_keyslots, NULL);
        return;
    }

    mode = MODE_CREATE;

    otpKeySlot_t keyslot;
    otp_initialize_key(&keyslot);
    add_keyslot(&keyslot);

    otp_print_public_id(&keyslot, new_key_public_id);
    otpKeySecrets_t secrets;
    otp_derive_keys(&keyslot, &secrets);
    otp_print_private_id(&secrets, new_key_private_id);
    otp_print_aes_key(&secrets, new_key_aes_1, new_key_aes_2, new_key_aes_3);

    UX_MENU_DISPLAY(0, menu_new_key, NULL);
}

const ux_menu_entry_t menu_main[] = {
    {NULL, menu_list_init, MODE_CREATE, NULL, "OTP keys", NULL, 0, 0},
    {NULL, menu_new_entry, 0, NULL, "New random key", NULL, 0, 0},
    {NULL, menu_list_init, MODE_REMOVE, NULL, "Delete key", NULL, 0, 0},
    {menu_reset_all, NULL, 0, NULL, "Delete all", NULL, 0, 0},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

void sample_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E00);
                }

                // default no error
                THROW(0x9000);
            }
            CATCH_OTHER(e) {
                switch (e & 0xFFFFF000) {
                case 0x6000:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    // TODO here: error processing, memory wipes ?
                    break;
                case 0x9000:
                    // ok
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    // return_to_dashboard:
    return;
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
    // no break is intentional
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            if (UX_ALLOWED) {
                UX_REDISPLAY();
            }
        });
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            if (N_storage.magic != STORAGE_MAGIC) {
                uint32_t magic;
                magic = STORAGE_MAGIC;
                nvm_write(&N_storage.magic, (void *)&magic, sizeof(uint32_t));
                reset_keyslots();
            }

            increment_bootcounts();
            otp_reset_token_counter();

            USB_power(1);

            mode = MODE_NONE;
            UX_MENU_DISPLAY(0, menu_main, NULL);

            sample_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();

    return 0;
}
