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

#ifndef USB_KEYBOARD_H

#define USB_KEYBOARD_H

void usb_kbd_send_char(char ch);
void usb_kbd_send_string(char* s);
void usb_kbd_send_enter();

#endif
