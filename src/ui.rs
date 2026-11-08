use crate::pigeonhole::{
    default_spool_dir, default_vault_mailbox_path, MessageDirection, ReplicaReadReply,
    VaultMailbox, write_private_atomic,
};
use crate::sphinx::{ConsensusTopology, SphinxEngine};
use crate::virtual_keyboard::VirtualKeyboardState;
use rand::Rng;
use slint::VecModel;
use std::cell::RefCell;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

slint::slint! {
    import { Button, LineEdit, TextEdit, ScrollView, CheckBox } from "std-widgets.slint";

    export struct MessageItem {
        id: string,
        direction: string,
        party: string,
        preview: string,
        time_str: string,
        quantum_state: string,
        secrecy: string,
        raw_plaintext: string,
    }

    export struct ContactItem {
        username: string,
        box_id: string,
        avatar: image,
    }

    export component MainWindow inherits Window {
        title: "Katzenpost Sovereign Client — Katzen Air-Gapped";
        min_width: 920px;
        min_height: 720px;
        background: #151821;

        in-out property <int> active_tab: 0; // 0: Composer, 1: Mailbox, 2: Contacts

        // Composer properties
        in-out property <string> recipient_box_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        in-out property <string> message_body: "";
        in-out property <string> send_feedback_banner: "";
        in-out property <string> send_feedback_detail: "";
        in-out property <string> secrecy_stars: "Input method: physical keyboard";
        in-out property <string> secrecy_desc: "No input method guarantees protection against a compromised device.";
        in-out property <string> quantum_status: "🐱 Quantum State: Superposition (Schrödinger Vault Sealed)";
        in-out property <string> opsec_tip: "OPSEC: Optical diode / removable media physically isolates Vault from network observation.";
        in-out property <bool> use_virtual_kbd: true;
        in-out property <bool> shift_active: false;
        in-out property <bool> auto_shuffle_on_click: false;
        in-out property <[string]> num_keys: ["7", "2", "9", "0", "4", "1", "8", "5", "3", "6"];
        in-out property <[string]> let1_keys: ["m", "q", "z", "a", "p", "w", "s", "x", "e", "d"];
        in-out property <[string]> let2_keys: ["c", "r", "f", "v", "t", "g", "b", "y", "h"];
        in-out property <[string]> let3_keys: ["n", "u", "j", "i", "k", "o", "l"];
        in-out property <[string]> sym1_keys: ["@", "#", "!", "?", ".", ",", ":", ";", "$", "%"];
        in-out property <[string]> sym2_keys: ["&", "*", "-", "+", "=", "/", "_", "\"", "'", "("];
        in-out property <string> my_box_id: "Box Identity: Initializing...";
        in-out property <image> operator_avatar;
        in-out property <string> status_log: "Ready.";

        // Mailbox properties
        in-out property <[MessageItem]> messages_model: [];
        in-out property <string> selected_message_text: "";
        in-out property <string> selected_message_info: "Select a message from the list to view decrypted plaintext.";
        in-out property <string> ingest_raw_hex: "";

        // Contacts properties
        in-out property <[ContactItem]> contacts_model: [];
        in-out property <string> new_contact_username: "";
        in-out property <string> new_contact_box_id: "";

        // Callbacks
        callback switch_tab(int);
        callback send_message_clicked();
        callback toggle_virtual_kbd(bool);
        callback shuffle_keys_clicked();
        callback virtual_key_pressed(string);
        callback virtual_backspace_pressed();
        callback virtual_clear_pressed();
        callback virtual_shift_toggled();
        callback export_spool_clicked();
        callback poll_mailbox_clicked();

        callback select_message_clicked(string, string);
        callback ingest_reply_clicked();

        callback add_contact_clicked();
        callback use_contact_clicked(string);

        // Vault Lock / Authentication Properties
        in-out property <bool> is_unlocked: false;
        in-out property <bool> is_new_vault: false;
        in-out property <string> unlock_passphrase: "";
        in-out property <string> unlock_confirm_passphrase: "";
        in-out property <string> unlock_error: "";
        callback unlock_vault_clicked();
        callback unlock_key_pressed(string);
        callback unlock_backspace_pressed();
        callback unlock_clear_pressed();

        if !root.is_unlocked : VerticalLayout {
            padding: 30px;
            spacing: 16px;
            alignment: center;

            HorizontalLayout {
                alignment: center;
                VerticalLayout {
                    spacing: 6px;
                    width: 580px;

                    Text {
                        text: "KATZENPOST SOVEREIGN VAULT";
                        color: #4fd1c5;
                        font_size: 22px;
                        font_weight: 800;
                        horizontal_alignment: center;
                    }
                    Text {
                        text: root.is_new_vault ? "INITIALIZE NEW ENCRYPTED VAULT" : "ENCRYPTED VAULT LOCKED";
                        color: root.is_new_vault ? #68d391 : #ecc94b;
                        font_size: 13px;
                        font_weight: 700;
                        font_family: "monospace";
                        horizontal_alignment: center;
                    }
                    Text {
                        text: root.is_new_vault
                            ? "Set a master passphrase (minimum 12 characters) to initialize your sovereign offline mailbox. All keys, contacts and messages are protected with Argon2id + XChaCha20-Poly1305."
                            : "Enter your master passphrase to unlock and decrypt your offline identity, cryptographic keys, contacts, and message queue.";
                        color: #a0aec0;
                        font_size: 12px;
                        horizontal_alignment: center;
                        wrap: word-wrap;
                    }
                }
            }

            HorizontalLayout {
                alignment: center;
                Rectangle {
                    background: #1e2330;
                    border_radius: 10px;
                    border_width: 1px;
                    border_color: #2d3748;
                    width: 580px;

                    VerticalLayout {
                        padding: 22px;
                        spacing: 14px;

                        if root.unlock_error != "" : Rectangle {
                            background: #4a1515;
                            border_radius: 6px;
                            border_width: 1px;
                            border_color: #e53e3e;
                            HorizontalLayout {
                                padding: 10px;
                                Text {
                                    text: "Warning: " + root.unlock_error;
                                    color: #feb2b2;
                                    font_size: 12px;
                                    font_weight: 600;
                                    wrap: word-wrap;
                                }
                            }
                        }

                        VerticalLayout {
                            spacing: 5px;
                            Text {
                                text: root.is_new_vault ? "New Master Passphrase:" : "Vault Passphrase:";
                                color: #e2e8f0;
                                font_size: 13px;
                                font_weight: 600;
                            }
                            LineEdit {
                                input_type: password;
                                text <=> root.unlock_passphrase;
                                placeholder_text: "Enter passphrase...";
                                accepted => { root.unlock_vault_clicked(); }
                            }
                        }

                        if root.is_new_vault : VerticalLayout {
                            spacing: 5px;
                            Text {
                                text: "Confirm Passphrase:";
                                color: #e2e8f0;
                                font_size: 13px;
                                font_weight: 600;
                            }
                            LineEdit {
                                input_type: password;
                                text <=> root.unlock_confirm_passphrase;
                                placeholder_text: "Confirm passphrase...";
                                accepted => { root.unlock_vault_clicked(); }
                            }
                        }

                        Button {
                            text: root.is_new_vault ? "Initialize & Open Vault" : "Decrypt & Unlock Vault";
                            primary: true;
                            height: 38px;
                            clicked => { root.unlock_vault_clicked(); }
                        }

                        Rectangle {
                            background: #141824;
                            border_radius: 8px;
                            border_width: 1px;
                            border_color: #3182ce;

                            VerticalLayout {
                                padding: 10px;
                                spacing: 6px;

                                HorizontalLayout {
                                    Text {
                                        text: "Anti-Keylogger On-Screen Pad (Mouse Coordinate Scrambler)";
                                        color: #63b3ed;
                                        font_size: 11px;
                                        font_weight: 600;
                                        vertical_alignment: center;
                                        horizontal_stretch: 1;
                                    }
                                    Button {
                                        text: "Shuffle";
                                        clicked => { root.shuffle_keys_clicked(); }
                                    }
                                }

                                HorizontalLayout {
                                    spacing: 4px;
                                    for k in root.num_keys : Rectangle {
                                        horizontal_stretch: 1;
                                        height: 28px;
                                        background: ta_un_num.pressed ? #3182ce : (ta_un_num.has_hover ? #2d3748 : #1e2536);
                                        border_radius: 4px;
                                        border_width: 1px;
                                        border_color: #3a465e;
                                        Text { text: k; color: #f7fafc; font_size: 12px; font_weight: 700; horizontal_alignment: center; vertical_alignment: center; }
                                        ta_un_num := TouchArea { clicked => { root.unlock_key_pressed(k); } }
                                    }
                                }

                                HorizontalLayout {
                                    spacing: 4px;
                                    for k in root.let1_keys : Rectangle {
                                        horizontal_stretch: 1;
                                        height: 28px;
                                        background: ta_un_l1.pressed ? #2f855a : (ta_un_l1.has_hover ? #2d3748 : #232b3e);
                                        border_radius: 4px;
                                        border_width: 1px;
                                        border_color: #4a5568;
                                        Text { text: k; color: #ffffff; font_size: 12px; font_weight: 700; horizontal_alignment: center; vertical_alignment: center; }
                                        ta_un_l1 := TouchArea { clicked => { root.unlock_key_pressed(k); } }
                                    }
                                }

                                HorizontalLayout {
                                    spacing: 4px;
                                    for k in root.let2_keys : Rectangle {
                                        horizontal_stretch: 1;
                                        height: 28px;
                                        background: ta_un_l2.pressed ? #2f855a : (ta_un_l2.has_hover ? #2d3748 : #232b3e);
                                        border_radius: 4px;
                                        border_width: 1px;
                                        border_color: #4a5568;
                                        Text { text: k; color: #ffffff; font_size: 12px; font_weight: 700; horizontal_alignment: center; vertical_alignment: center; }
                                        ta_un_l2 := TouchArea { clicked => { root.unlock_key_pressed(k); } }
                                    }
                                }

                                HorizontalLayout {
                                    spacing: 6px;
                                    Button {
                                        text: "Backspace";
                                        clicked => { root.unlock_backspace_pressed(); }
                                    }
                                    Button {
                                        text: "Clear";
                                        clicked => { root.unlock_clear_pressed(); }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if root.is_unlocked : VerticalLayout {
            padding: 18px;
            spacing: 12px;

            // Header Banner
            HorizontalLayout {
                spacing: 14px;
                Image {
                    source: root.operator_avatar;
                    width: 44px;
                    height: 44px;
                    image-fit: contain;
                }
                VerticalLayout {
                    spacing: 2px;
                    horizontal_stretch: 1;
                    Text {
                        text: "KATZENPOST SOVEREIGN VAULT";
                        color: #4fd1c5;
                        font_size: 17px;
                        font_weight: 700;
                    }
                    Text {
                        text: root.my_box_id;
                        color: #a0aec0;
                        font_size: 11px;
                        font_family: "monospace";
                    }
                }
            }

            // Tab Navigation Bar
            HorizontalLayout {
                spacing: 8px;
                height: 38px;

                Rectangle {
                    background: root.active_tab == 0 ? #2b6cb0 : #1e2330;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: root.active_tab == 0 ? #63b3ed : #2d3748;
                    TouchArea {
                        clicked => { root.switch_tab(0); }
                    }
                    Text {
                        text: "✍️ Composer & Virtual Keyboard";
                        color: root.active_tab == 0 ? #ffffff : #a0aec0;
                        font_size: 13px;
                        font_weight: 600;
                        vertical_alignment: center;
                        horizontal_alignment: center;
                    }
                }

                Rectangle {
                    background: root.active_tab == 1 ? #2b6cb0 : #1e2330;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: root.active_tab == 1 ? #63b3ed : #2d3748;
                    TouchArea {
                        clicked => { root.switch_tab(1); }
                    }
                    Text {
                        text: "📬 Mailbox & Inbox Spool";
                        color: root.active_tab == 1 ? #ffffff : #a0aec0;
                        font_size: 13px;
                        font_weight: 600;
                        vertical_alignment: center;
                        horizontal_alignment: center;
                    }
                }

                Rectangle {
                    background: root.active_tab == 2 ? #2b6cb0 : #1e2330;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: root.active_tab == 2 ? #63b3ed : #2d3748;
                    TouchArea {
                        clicked => { root.switch_tab(2); }
                    }
                    Text {
                        text: "👥 Contacts & Key Avatars";
                        color: root.active_tab == 2 ? #ffffff : #a0aec0;
                        font_size: 13px;
                        font_weight: 600;
                        vertical_alignment: center;
                        horizontal_alignment: center;
                    }
                }
            }

            // -----------------------------------------------------------------
            // TAB 0: COMPOSER & VIRTUAL KEYBOARD
            // -----------------------------------------------------------------
            if root.active_tab == 0 : VerticalLayout {
                spacing: 10px;

                // Quantum Metaphor & Secrecy Score Box
                Rectangle {
                    background: #1e2330;
                    border_radius: 8px;
                    border_width: 1px;
                    border_color: #2d3748;
                    height: 64px;

                    VerticalLayout {
                        padding: 8px;
                        spacing: 4px;

                        HorizontalLayout {
                            Text {
                                text: root.quantum_status;
                                color: #ecc94b;
                                font_size: 12px;
                                font_weight: 600;
                            }
                            Text {
                                text: root.secrecy_stars;
                                color: #68d391;
                                font_size: 13px;
                                font_weight: 700;
                                horizontal_alignment: right;
                            }
                        }

                        Text {
                            text: root.secrecy_desc;
                            color: #cbd5e0;
                            font_size: 11px;
                        }
                    }
                }

                // Recipient & Message Inputs
                HorizontalLayout {
                    spacing: 8px;
                    Text {
                        text: "Recipient (Box ID):";
                        color: #e2e8f0;
                        vertical_alignment: center;
                        font_size: 12px;
                    }
                    LineEdit {
                        text <=> root.recipient_box_id;
                        placeholder_text: "Enter 32-byte Hex Box ID (or pick from Contacts)...";
                        horizontal_stretch: 1;
                    }
                }

                Text {
                    text: "Message Payload to Encrypt:";
                    color: #e2e8f0;
                    font_size: 12px;
                }

                TextEdit {
                    text <=> root.message_body;
                    height: 100px;
                    font_size: 13px;
                }

                // Virtual Keyboard Toggle & Section
                HorizontalLayout {
                    spacing: 8px;
                    alignment: start;
                    CheckBox {
                        checked <=> root.use_virtual_kbd;
                        toggled => {
                            root.toggle_virtual_kbd(root.use_virtual_kbd);
                        }
                    }
                    Text {
                        text: "Optional on-screen keyboard";
                        color: #edf2f7;
                        font_size: 12px;
                        font_weight: 600;
                        vertical_alignment: center;
                    }
                    Rectangle { horizontal_stretch: 1; }
                    if root.use_virtual_kbd : CheckBox {
                        text: "Auto-shuffle on click";
                        checked <=> root.auto_shuffle_on_click;
                    }
                    if root.use_virtual_kbd : Button {
                        text: "Shuffle Keys 🔀";
                        clicked => { root.shuffle_keys_clicked(); }
                    }
                }

                if root.use_virtual_kbd : Rectangle {
                    background: #141824;
                    border_radius: 8px;
                    border_width: 1px;
                    border_color: #3182ce;

                    VerticalLayout {
                        padding: 10px;
                        spacing: 6px;

                        Text {
                            text: "Click keys below to compose message (Randomized Intra-Group Layout — immune to hardware/X11 keyloggers):";
                            color: #63b3ed;
                            font_size: 11px;
                        }

                        // Numbers Row
                        HorizontalLayout {
                            spacing: 5px;
                            Text { text: "NUM"; color: #90cdf4; font_size: 10px; font_weight: 700; width: 36px; vertical_alignment: center; }
                            for k in root.num_keys : Rectangle {
                                horizontal_stretch: 1;
                                height: 30px;
                                background: ta_num.pressed ? #3182ce : (ta_num.has_hover ? #2d3748 : #1e2536);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: ta_num.has_hover ? #63b3ed : #3a465e;
                                Text {
                                    text: k;
                                    color: #f7fafc;
                                    font_size: 13px;
                                    font_weight: 700;
                                    font_family: "monospace";
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_num := TouchArea {
                                    clicked => { root.virtual_key_pressed(k); }
                                }
                            }
                        }

                        // Letters Row 1 (10 keys)
                        HorizontalLayout {
                            spacing: 5px;
                            Text { text: "LET"; color: #68d391; font_size: 10px; font_weight: 700; width: 36px; vertical_alignment: center; }
                            for k in root.let1_keys : Rectangle {
                                horizontal_stretch: 1;
                                height: 32px;
                                background: ta_l1.pressed ? #2f855a : (ta_l1.has_hover ? #2d3748 : #232b3e);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: ta_l1.has_hover ? #68d391 : #4a5568;
                                Text {
                                    text: k;
                                    color: #ffffff;
                                    font_size: 14px;
                                    font_weight: 700;
                                    font_family: "monospace";
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_l1 := TouchArea {
                                    clicked => { root.virtual_key_pressed(k); }
                                }
                            }
                        }

                        // Letters Row 2 (9 keys)
                        HorizontalLayout {
                            spacing: 5px;
                            Rectangle { width: 36px; }
                            for k in root.let2_keys : Rectangle {
                                horizontal_stretch: 1;
                                height: 32px;
                                background: ta_l2.pressed ? #2f855a : (ta_l2.has_hover ? #2d3748 : #232b3e);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: ta_l2.has_hover ? #68d391 : #4a5568;
                                Text {
                                    text: k;
                                    color: #ffffff;
                                    font_size: 14px;
                                    font_weight: 700;
                                    font_family: "monospace";
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_l2 := TouchArea {
                                    clicked => { root.virtual_key_pressed(k); }
                                }
                            }
                        }

                        // Letters Row 3 (7 keys + CAPS toggle)
                        HorizontalLayout {
                            spacing: 5px;
                            Rectangle {
                                width: 64px;
                                height: 32px;
                                background: root.shift_active ? #d69e2e : (ta_shift.has_hover ? #4a5568 : #2d3748);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: root.shift_active ? #fbd38d : #718096;
                                Text {
                                    text: root.shift_active ? "⇧ CAPS ON" : "⇧ Shift";
                                    color: root.shift_active ? #1a202c : #edf2f7;
                                    font_size: 11px;
                                    font_weight: 700;
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_shift := TouchArea {
                                    clicked => { root.virtual_shift_toggled(); }
                                }
                            }
                            for k in root.let3_keys : Rectangle {
                                horizontal_stretch: 1;
                                height: 32px;
                                background: ta_l3.pressed ? #2f855a : (ta_l3.has_hover ? #2d3748 : #232b3e);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: ta_l3.has_hover ? #68d391 : #4a5568;
                                Text {
                                    text: k;
                                    color: #ffffff;
                                    font_size: 14px;
                                    font_weight: 700;
                                    font_family: "monospace";
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_l3 := TouchArea {
                                    clicked => { root.virtual_key_pressed(k); }
                                }
                            }
                        }

                        // Symbols Row 1
                        HorizontalLayout {
                            spacing: 5px;
                            Text { text: "SYM"; color: #fbb6ce; font_size: 10px; font_weight: 700; width: 36px; vertical_alignment: center; }
                            for k in root.sym1_keys : Rectangle {
                                horizontal_stretch: 1;
                                height: 28px;
                                background: ta_s1.pressed ? #97266d : (ta_s1.has_hover ? #2d3748 : #1e2230);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: ta_s1.has_hover ? #fbb6ce : #3a4052;
                                Text {
                                    text: k;
                                    color: #fed7e2;
                                    font_size: 12px;
                                    font_weight: 700;
                                    font_family: "monospace";
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_s1 := TouchArea {
                                    clicked => { root.virtual_key_pressed(k); }
                                }
                            }
                        }

                        // Symbols Row 2
                        HorizontalLayout {
                            spacing: 5px;
                            Rectangle { width: 36px; }
                            for k in root.sym2_keys : Rectangle {
                                horizontal_stretch: 1;
                                height: 28px;
                                background: ta_s2.pressed ? #97266d : (ta_s2.has_hover ? #2d3748 : #1e2230);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: ta_s2.has_hover ? #fbb6ce : #3a4052;
                                Text {
                                    text: k;
                                    color: #fed7e2;
                                    font_size: 12px;
                                    font_weight: 700;
                                    font_family: "monospace";
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_s2 := TouchArea {
                                    clicked => { root.virtual_key_pressed(k); }
                                }
                            }
                        }

                        // Action Bar: SPACE, ENTER, BACKSPACE, CLEAR
                        HorizontalLayout {
                            spacing: 6px;
                            Rectangle { width: 36px; }

                            // SPACEBAR
                            Rectangle {
                                horizontal_stretch: 3;
                                height: 32px;
                                background: ta_space.pressed ? #3182ce : (ta_space.has_hover ? #3a465e : #262f42);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: #4a5568;
                                Text {
                                    text: "␣  SPACE";
                                    color: #edf2f7;
                                    font_size: 12px;
                                    font_weight: 700;
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_space := TouchArea {
                                    clicked => { root.virtual_key_pressed(" "); }
                                }
                            }

                            // ENTER / NEWLINE
                            Rectangle {
                                horizontal_stretch: 1;
                                height: 32px;
                                background: ta_enter.pressed ? #3182ce : (ta_enter.has_hover ? #3a465e : #262f42);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: #4a5568;
                                Text {
                                    text: "↵ ENTER";
                                    color: #edf2f7;
                                    font_size: 11px;
                                    font_weight: 700;
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_enter := TouchArea {
                                    clicked => { root.virtual_key_pressed("\n"); }
                                }
                            }

                            // BACKSPACE
                            Rectangle {
                                horizontal_stretch: 1;
                                height: 32px;
                                background: ta_bksp.pressed ? #c53030 : (ta_bksp.has_hover ? #4a3540 : #2d2632);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: #9b2c2c;
                                Text {
                                    text: "⌫ BKSP";
                                    color: #feb2b2;
                                    font_size: 11px;
                                    font_weight: 700;
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_bksp := TouchArea {
                                    clicked => { root.virtual_backspace_pressed(); }
                                }
                            }

                            // CLEAR
                            Rectangle {
                                horizontal_stretch: 1;
                                height: 32px;
                                background: ta_clr.pressed ? #9b2c2c : (ta_clr.has_hover ? #4a2c2c : #2a2024);
                                border_radius: 4px;
                                border_width: 1px;
                                border_color: #742a2a;
                                Text {
                                    text: "🗑 CLEAR";
                                    color: #fc8181;
                                    font_size: 11px;
                                    font_weight: 700;
                                    horizontal_alignment: center;
                                    vertical_alignment: center;
                                }
                                ta_clr := TouchArea {
                                    clicked => { root.virtual_clear_pressed(); }
                                }
                            }
                        }
                    }
                }

                // Action Buttons
                HorizontalLayout {
                    spacing: 12px;

                    Button {
                        text: root.message_body == "" ? "Write a Message Above to Send" : "Construct & Dispatch Sphinx Packet 🚀";
                        primary: true;
                        enabled: root.message_body != "";
                        clicked => { root.send_message_clicked(); }
                    }

                    Button {
                        text: "Flush USB Spool Outbox";
                        clicked => { root.export_spool_clicked(); }
                    }

                    Button {
                        text: "Poll Pigeonhole Mailbox";
                        clicked => { root.poll_mailbox_clicked(); }
                    }
                }

                // Visual Confirmation Banner after sending
                if root.send_feedback_banner != "" : Rectangle {
                    background: #1c3d36;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: #48bb78;
                    height: 56px;

                    HorizontalLayout {
                        padding: 8px;
                        spacing: 10px;
                        VerticalLayout {
                            spacing: 2px;
                            horizontal_stretch: 1;
                            Text {
                                text: root.send_feedback_banner;
                                color: #68d391;
                                font_size: 12px;
                                font_weight: 700;
                            }
                            Text {
                                text: root.send_feedback_detail;
                                color: #e2e8f0;
                                font_size: 11px;
                                font_family: "monospace";
                            }
                        }
                        Button {
                            text: "📬 Vedi in Mailbox ➔";
                            clicked => { root.switch_tab(1); }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // TAB 1: MAILBOX & INBOX SPOOL
            // -----------------------------------------------------------------
            if root.active_tab == 1 : VerticalLayout {
                spacing: 10px;

                Text {
                    text: "📬 ASYNCHRONOUS PIGEONHOLE MAILBOX & QUANTUM STATES";
                    color: #4fd1c5;
                    font_size: 15px;
                    font_weight: 700;
                }

                Text {
                    text: "Unobserved messages remain in quantum superposition (sealed). Wavefunction collapses upon local vault observation.";
                    color: #a0aec0;
                    font_size: 11px;
                }

                // Ingest Box
                Rectangle {
                    background: #1e2330;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: #2d3748;
                    height: 52px;

                    HorizontalLayout {
                        padding: 8px;
                        spacing: 8px;
                        Text {
                            text: "Inbound Envelope (Hex):";
                            color: #e2e8f0;
                            font_size: 12px;
                            vertical_alignment: center;
                        }
                        LineEdit {
                            text <=> root.ingest_raw_hex;
                            placeholder_text: "Paste raw hex of ReplicaReadReply envelope received via USB spool/QR...";
                            horizontal_stretch: 1;
                        }
                        Button {
                            text: "Decrypt & Observe";
                            primary: true;
                            clicked => { root.ingest_reply_clicked(); }
                        }
                    }
                }

                Text {
                    text: "Messages Stored in Local Vault Mailbox:";
                    color: #e2e8f0;
                    font_size: 12px;
                    font_weight: 600;
                }

                ScrollView {
                    height: 200px;
                    VerticalLayout {
                        spacing: 6px;
                        for msg in root.messages_model : Rectangle {
                            background: #1a1e29;
                            border_radius: 6px;
                            border_width: 1px;
                            border_color: #2d3748;
                            height: 60px;

                            TouchArea {
                                clicked => { root.select_message_clicked(msg.raw_plaintext, msg.id); }
                            }

                            VerticalLayout {
                                padding: 6px;
                                spacing: 2px;
                                HorizontalLayout {
                                    Text {
                                        text: msg.direction;
                                        color: msg.direction == "INBOUND [↓]" ? #68d391 : #63b3ed;
                                        font_size: 11px;
                                        font_weight: 700;
                                        width: 110px;
                                    }
                                    Text {
                                        text: "Peer: " + msg.party;
                                        color: #e2e8f0;
                                        font_size: 11px;
                                        font_family: "monospace";
                                        horizontal_stretch: 1;
                                    }
                                    Text {
                                        text: msg.secrecy;
                                        color: #ecc94b;
                                        font_size: 11px;
                                        horizontal_alignment: right;
                                    }
                                }
                                HorizontalLayout {
                                    Text {
                                        text: msg.quantum_state;
                                        color: #cbd5e0;
                                        font_size: 11px;
                                        horizontal_stretch: 1;
                                    }
                                    Text {
                                        text: "Preview: " + msg.preview;
                                        color: #718096;
                                        font_size: 10px;
                                    }
                                }
                            }
                        }
                    }
                }

                // Inspection pane for selected message
                Rectangle {
                    background: #1e2330;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: #2d3748;
                    height: 96px;

                    VerticalLayout {
                        padding: 8px;
                        spacing: 4px;
                        Text {
                            text: root.selected_message_info;
                            color: #ecc94b;
                            font_size: 11px;
                            font_weight: 600;
                        }
                        TextEdit {
                            text: root.selected_message_text;
                            read_only: true;
                            font_size: 12px;
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // TAB 2: CONTACTS & KEY AVATARS
            // -----------------------------------------------------------------
            if root.active_tab == 2 : VerticalLayout {
                spacing: 10px;

                Text {
                    text: "👥 CONTACTS & DETERMINISTIC CRYPTOGRAPHIC AVATARS";
                    color: #4fd1c5;
                    font_size: 15px;
                    font_weight: 700;
                }

                Text {
                    text: "Contact icons are visual aids. Verify the full Box ID through a trusted channel.";
                    color: #a0aec0;
                    font_size: 11px;
                }

                // Add Contact Box
                Rectangle {
                    background: #1e2330;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: #2d3748;
                    height: 52px;

                    HorizontalLayout {
                        padding: 8px;
                        spacing: 8px;
                        Text {
                            text: "New Contact:";
                            color: #e2e8f0;
                            font_size: 12px;
                            vertical_alignment: center;
                        }
                        LineEdit {
                            text <=> root.new_contact_username;
                            placeholder_text: "Username (e.g. Alice)...";
                            width: 160px;
                        }
                        LineEdit {
                            text <=> root.new_contact_box_id;
                            placeholder_text: "32-byte Hex Box ID (64 hex characters)...";
                            horizontal_stretch: 1;
                        }
                        Button {
                            text: "Add & Generate Avatar 🎨";
                            primary: true;
                            clicked => { root.add_contact_clicked(); }
                        }
                    }
                }

                Text {
                    text: "Sovereign Contacts Saved in Vault:";
                    color: #e2e8f0;
                    font_size: 12px;
                    font_weight: 600;
                }

                ScrollView {
                    height: 310px;
                    VerticalLayout {
                        spacing: 8px;
                        for contact in root.contacts_model : Rectangle {
                            background: #1a1e29;
                            border_radius: 6px;
                            border_width: 1px;
                            border_color: #2d3748;
                            height: 72px;

                            HorizontalLayout {
                                padding: 8px;
                                spacing: 14px;
                                Image {
                                    source: contact.avatar;
                                    width: 56px;
                                    height: 56px;
                                    image-fit: contain;
                                }
                                VerticalLayout {
                                    spacing: 4px;
                                    horizontal_stretch: 1;
                                    Text {
                                        text: contact.username;
                                        color: #4fd1c5;
                                        font_size: 14px;
                                        font_weight: 700;
                                    }
                                    Text {
                                        text: "Box ID: " + contact.box_id;
                                        color: #cbd5e0;
                                        font_size: 11px;
                                        font_family: "monospace";
                                    }
                                    Text {
                                        text: "Pure Rust deterministic identicon — immutable & verifiable";
                                        color: #718096;
                                        font_size: 10px;
                                    }
                                }
                                Button {
                                    text: "Send Message ➔";
                                    clicked => { root.use_contact_clicked(contact.box_id); }
                                }
                            }
                        }
                    }
                }
            }

            // Bottom OPSEC Tip & Status Log
            Rectangle {
                background: #181b24;
                border_radius: 6px;

                HorizontalLayout {
                    padding: 6px;
                    Text {
                        text: root.status_log;
                        color: #9ae6b4;
                        font_size: 11px;
                        horizontal_stretch: 1;
                    }
                    Text {
                        text: root.opsec_tip;
                        color: #718096;
                        font_size: 11px;
                        horizontal_alignment: right;
                    }
                }
            }
        }
    }
}

fn reload_ui_models(ui: &MainWindow, mailbox: &VaultMailbox) {
    let msg_items: Vec<MessageItem> = mailbox
        .messages
        .iter()
        .map(|m| {
            let dir = match m.direction {
                MessageDirection::Inbound => "INBOUND [↓]",
                MessageDirection::Outbound => "OUTBOUND [↑]",
            };
            let party = if m.direction == MessageDirection::Inbound {
                &m.sender
            } else {
                &m.recipient
            };
            let party_short = if party.len() > 20 {
                format!("{}...", &party[0..20])
            } else {
                party.clone()
            };
            MessageItem {
                id: m.id.clone().into(),
                direction: dir.into(),
                party: party_short.into(),
                preview: m.plaintext.chars().take(40).collect::<String>().into(),
                time_str: format!("{}", m.timestamp).into(),
                quantum_state: m.quantum_state.clone().into(),
                secrecy: format!("{} stars", m.secrecy_stars).into(),
                raw_plaintext: m.plaintext.clone().into(),
            }
        })
        .collect();
    ui.set_messages_model(Rc::new(VecModel::from(msg_items)).into());

    let contact_items: Vec<ContactItem> = mailbox
        .contacts
        .iter()
        .map(|c| {
            let avatar_img = c.identicon().to_slint_image(8);
            ContactItem {
                username: c.username.clone().into(),
                box_id: c.box_id_hex.clone().into(),
                avatar: avatar_img,
            }
        })
        .collect();
    ui.set_contacts_model(Rc::new(VecModel::from(contact_items)).into());
}

pub fn run_gui() -> Result<(), String> {
    if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
        println!("==> No active display detected (DISPLAY / WAYLAND_DISPLAY unset).");
        println!("==> Starting interactive Sovereign TUI with partitioned virtual keyboard...\n");
        return run_interactive_tui();
    }

    let mailbox_path = default_vault_mailbox_path();
    let is_new = !mailbox_path.exists();

    let main_window = MainWindow::new().map_err(|e| format!("Slint GUI init error: {}", e))?;
    let mut kbd_state = VirtualKeyboardState::new();
    kbd_state.is_enabled = true;
    kbd_state.used_for_composition = true;

    main_window.set_is_unlocked(false);
    main_window.set_is_new_vault(is_new);
    main_window.set_unlock_error("".into());
    main_window.set_unlock_passphrase("".into());
    main_window.set_unlock_confirm_passphrase("".into());

    let update_rows = {
        let handle = main_window.as_weak();
        move |kbd: &VirtualKeyboardState| {
            if let Some(ui) = handle.upgrade() {
                let n_vec: Vec<slint::SharedString> = kbd.numbers.iter().map(|c| c.to_string().into()).collect();
                ui.set_num_keys(Rc::new(VecModel::from(n_vec)).into());

                let l1_vec: Vec<slint::SharedString> = kbd.letters[0..10.min(kbd.letters.len())]
                    .iter()
                    .map(|c| kbd.get_letter_char(*c).to_string().into())
                    .collect();
                let l2_vec: Vec<slint::SharedString> = kbd.letters[10..19.min(kbd.letters.len())]
                    .iter()
                    .map(|c| kbd.get_letter_char(*c).to_string().into())
                    .collect();
                let l3_vec: Vec<slint::SharedString> = kbd.letters[19..kbd.letters.len()]
                    .iter()
                    .map(|c| kbd.get_letter_char(*c).to_string().into())
                    .collect();
                ui.set_let1_keys(Rc::new(VecModel::from(l1_vec)).into());
                ui.set_let2_keys(Rc::new(VecModel::from(l2_vec)).into());
                ui.set_let3_keys(Rc::new(VecModel::from(l3_vec)).into());

                let s1_vec: Vec<slint::SharedString> = kbd.symbols[0..10.min(kbd.symbols.len())]
                    .iter()
                    .map(|c| c.to_string().into())
                    .collect();
                let s2_vec: Vec<slint::SharedString> = kbd.symbols[10..kbd.symbols.len()]
                    .iter()
                    .map(|c| c.to_string().into())
                    .collect();
                ui.set_sym1_keys(Rc::new(VecModel::from(s1_vec)).into());
                ui.set_sym2_keys(Rc::new(VecModel::from(s2_vec)).into());
                ui.set_shift_active(kbd.shift_active);

                let score = kbd.compute_secrecy_score();
                let star_text = score.shielding_level.clone();
                ui.set_secrecy_stars(star_text.into());
                ui.set_secrecy_desc(score.opsec_note.into());
            }
        }
    };

    update_rows(&kbd_state);

    let kbd_ref = Rc::new(RefCell::new(kbd_state));
    let mailbox_ref: Rc<RefCell<Option<VaultMailbox>>> = Rc::new(RefCell::new(None));
    let passphrase_ref: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));

    // Callback unlock key pressed
    {
        let ui_weak = main_window.as_weak();
        main_window.on_unlock_key_pressed(move |k_str| {
            if let Some(ui) = ui_weak.upgrade() {
                let mut pass = ui.get_unlock_passphrase().to_string();
                pass.push_str(k_str.as_str());
                ui.set_unlock_passphrase(pass.into());
            }
        });
    }

    // Callback unlock backspace pressed
    {
        let ui_weak = main_window.as_weak();
        main_window.on_unlock_backspace_pressed(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let mut pass = ui.get_unlock_passphrase().to_string();
                pass.pop();
                ui.set_unlock_passphrase(pass.into());
            }
        });
    }

    // Callback unlock clear pressed
    {
        let ui_weak = main_window.as_weak();
        main_window.on_unlock_clear_pressed(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_unlock_passphrase("".into());
                ui.set_unlock_confirm_passphrase("".into());
                ui.set_unlock_error("".into());
            }
        });
    }

    // Callback unlock vault clicked
    {
        let ui_weak = main_window.as_weak();
        let mbox_path = mailbox_path.clone();
        let mbox_rc = mailbox_ref.clone();
        let pass_rc = passphrase_ref.clone();

        main_window.on_unlock_vault_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let pass = ui.get_unlock_passphrase().to_string();
                let is_new_v = ui.get_is_new_vault();

                if is_new_v {
                    if pass.chars().count() < 12 {
                        ui.set_unlock_error("Vault passphrase must contain at least 12 characters".into());
                        return;
                    }
                    let confirm = ui.get_unlock_confirm_passphrase().to_string();
                    if pass != confirm {
                        ui.set_unlock_error("Vault passphrases do not match. Please verify.".into());
                        return;
                    }
                } else {
                    if pass.is_empty() {
                        ui.set_unlock_error("Please enter your vault passphrase.".into());
                        return;
                    }
                }

                match VaultMailbox::load_with_passphrase(&mbox_path, &pass) {
                    Ok(loaded_mbox) => {
                        let _ = crate::pigeonhole::set_cached_vault_passphrase(&pass);
                        *pass_rc.borrow_mut() = Some(pass);

                        let my_id = format!("Box ID: {}", loaded_mbox.identity.box_id_hex);
                        ui.set_my_box_id(my_id.into());
                        let op_avatar = loaded_mbox.identity.identicon().to_slint_image(8);
                        ui.set_operator_avatar(op_avatar);

                        reload_ui_models(&ui, &loaded_mbox);

                        *mbox_rc.borrow_mut() = Some(loaded_mbox);

                        ui.set_unlock_passphrase("".into());
                        ui.set_unlock_confirm_passphrase("".into());
                        ui.set_unlock_error("".into());
                        ui.set_is_unlocked(true);
                        ui.set_status_log("Vault successfully unlocked and verified.".into());
                    }
                    Err(e) => {
                        ui.set_unlock_error(format!("Authentication failed: {}", e).into());
                    }
                }
            }
        });
    }

    // Callback switch tab
    {
        let ui_weak = main_window.as_weak();
        main_window.on_switch_tab(move |tab| {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_active_tab(tab);
            }
        });
    }

    // Callback toggle virtual kbd
    {
        let kbd_rc = kbd_ref.clone();
        let ui_weak = main_window.as_weak();
        main_window.on_toggle_virtual_kbd(move |enabled| {
            let mut k = kbd_rc.borrow_mut();
            k.is_enabled = enabled;
            k.used_for_composition = enabled;
            let score = k.compute_secrecy_score();
            if let Some(ui) = ui_weak.upgrade() {
                let star_text = score.shielding_level.clone();
                ui.set_secrecy_stars(star_text.into());
                ui.set_secrecy_desc(score.opsec_note.into());
                if enabled {
                    ui.set_status_log("On-screen keyboard enabled; it does not protect against compromised software.".into());
                } else {
                    ui.set_status_log("Physical keyboard enabled.".into());
                }
            }
        });
    }

    // Callback shuffle keys
    {
        let kbd_rc = kbd_ref.clone();
        let ui_weak = main_window.as_weak();
        let update_fn = update_rows.clone();
        main_window.on_shuffle_keys_clicked(move || {
            let mut k = kbd_rc.borrow_mut();
            k.shuffle_within_groups();
            update_fn(&k);
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_status_log("Keys shuffled within partitions (mouse coordinates randomized).".into());
            }
        });
    }

    // Callback virtual key pressed
    {
        let kbd_rc = kbd_ref.clone();
        let ui_weak = main_window.as_weak();
        let update_fn = update_rows.clone();
        main_window.on_virtual_key_pressed(move |key_str| {
            if let Some(ui) = ui_weak.upgrade() {
                let mut current = ui.get_message_body().to_string();
                current.push_str(key_str.as_str());
                ui.set_message_body(current.into());

                let mut k = kbd_rc.borrow_mut();
                k.used_for_composition = true;
                if ui.get_auto_shuffle_on_click() {
                    k.shuffle_within_groups();
                    update_fn(&k);
                }
            }
        });
    }

    // Callback virtual backspace pressed
    {
        let ui_weak = main_window.as_weak();
        main_window.on_virtual_backspace_pressed(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let mut current = ui.get_message_body().to_string();
                current.pop();
                ui.set_message_body(current.into());
            }
        });
    }

    // Callback virtual clear pressed
    {
        let ui_weak = main_window.as_weak();
        main_window.on_virtual_clear_pressed(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_message_body("".into());
                ui.set_status_log("Message cleared via Virtual Keyboard.".into());
            }
        });
    }

    // Callback virtual shift toggled
    {
        let kbd_rc = kbd_ref.clone();
        let update_fn = update_rows.clone();
        main_window.on_virtual_shift_toggled(move || {
            let mut k = kbd_rc.borrow_mut();
            k.toggle_shift();
            update_fn(&k);
        });
    }

    // Callback send / deposit message
    {
        let mbox_rc = mailbox_ref.clone();
        let pass_rc = passphrase_ref.clone();
        let kbd_rc = kbd_ref.clone();
        let ui_weak = main_window.as_weak();
        let mbox_path = mailbox_path.clone();
        main_window.on_send_message_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let recip = ui.get_recipient_box_id().to_string();
                let body = ui.get_message_body().to_string();
                if body.trim().is_empty() {
                    ui.set_status_log("Write a message payload before sending.".into());
                    return;
                }
                if recip.trim().is_empty() {
                    ui.set_status_log("Enter a valid recipient Box ID before proceeding.".into());
                    return;
                }

                let k = kbd_rc.borrow();
                let score = k.compute_secrecy_score();
                let method = if k.used_for_composition {
                    "On-screen keyboard"
                } else {
                    "Physical Keyboard"
                };

                let mut mbox_guard = mbox_rc.borrow_mut();
                let mbox = match mbox_guard.as_mut() {
                    Some(m) => m,
                    None => return,
                };

                match mbox.deposit_draft(&recip, body.trim(), score.stars, method) {
                    Ok(replica_write) => {
                        let spool_root = default_spool_dir();
                        let outbox = spool_root.join("outbox");
                        let _ = fs::create_dir_all(&outbox);

                        let ts = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let rand_id: u16 = rand::thread_rng().gen();

                        let pki_candidates = [
                            spool_root.join("pki.cbor"),
                            PathBuf::from("config/pki.cbor"),
                            PathBuf::from("/run/katzenpost/pki.cbor"),
                        ];
                        let (topology, is_live_pki) = pki_candidates
                            .iter()
                            .find_map(|p| fs::read(p).ok().and_then(|bytes| ConsensusTopology::from_pki_document(&bytes).ok()))
                            .map(|topo| (topo, true))
                            .unwrap_or_else(|| (ConsensusTopology::generate_mock_consensus(100).0, false));

                        let packet_ext = if is_live_pki { "bin" } else { "demo" };
                        let fname = format!("packet_{}_{:04x}.{}", ts, rand_id, packet_ext);
                        let spx_path = outbox.join(&fname);

                        let selected_path = match topology.select_path() {
                            Ok(p) => p,
                            Err(e) => {
                                ui.set_status_log(format!("Path selection error: {e}").into());
                                return;
                            }
                        };
                        let pkt = match SphinxEngine::build_packet(&selected_path, "courier", &replica_write.encode()) {
                            Ok(p) => p,
                            Err(e) => {
                                ui.set_status_log(format!("Packet build error: {e}").into());
                                return;
                            }
                        };
                        if let Err(e) = write_private_atomic(&spx_path, &pkt.raw_bytes) {
                            ui.set_status_log(format!("Could not save Sphinx packet: {e}").into());
                            return;
                        }

                        let save_res = if let Some(ref p) = *pass_rc.borrow() {
                            mbox.save_with_passphrase(&mbox_path, p)
                        } else {
                            mbox.save(&mbox_path)
                        };
                        if let Err(e) = save_res {
                            ui.set_status_log(format!("Could not save encrypted vault: {e}").into());
                            return;
                        }

                        ui.set_message_body("".into());
                        reload_ui_models(&ui, mbox);

                        let banner = if is_live_pki {
                            "Sphinx packet constructed from live Katzenpost PKI consensus"
                        } else {
                            "Demo packet saved locally; live mixnet delivery unavailable"
                        };
                        ui.set_send_feedback_banner(banner.into());
                        ui.set_send_feedback_detail(
                            format!("Saved to: {}", spx_path.display()).into(),
                        );
                        ui.set_status_log(
                            format!(
                                "Encrypted for {} ({} B) -> saved to {}",
                                &recip[0..8.min(recip.len())],
                                replica_write.payload.len(),
                                spx_path.display()
                            )
                            .into(),
                        );
                        ui.set_quantum_status(
                            if is_live_pki { "Sphinx packet spooled in outbox" } else { "Demo packet stored locally" }.into(),
                        );
                    }
                    Err(e) => {
                        ui.set_status_log(format!("Deposit encryption error: {}", e).into());
                    }
                }
            }
        });
    }

    // Callback export / flush spool
    {
        let ui_weak = main_window.as_weak();
        main_window.on_export_spool_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let spool_root = default_spool_dir();
                let outbox = spool_root.join("outbox");
                let _ = fs::create_dir_all(&outbox);

                ui.set_status_log(
                    format!("Demo outbox at {}. Live transmission requires real PKI and a compatible transport.", outbox.display()).into(),
                );

            }
        });
    }

    // Callback poll mailbox
    {
        let ui_weak = main_window.as_weak();
        main_window.on_poll_mailbox_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_status_log("SURBs generated for anonymous polling of Pigeonhole mailbox.".into());
                ui.set_quantum_status("🐱 Quantum State: Superposition awaiting observation".into());
            }
        });
    }

    // Callback select message to inspect
    {
        let ui_weak = main_window.as_weak();
        main_window.on_select_message_clicked(move |raw_text, id| {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_selected_message_text(raw_text);
                ui.set_selected_message_info(format!("Message ID: {} — Decrypted and observed in Vault:", id).into());
                ui.set_status_log("Message selected and inspected.".into());
            }
        });
    }

    // Callback ingest reply envelope
    {
        let mbox_rc = mailbox_ref.clone();
        let pass_rc = passphrase_ref.clone();
        let ui_weak = main_window.as_weak();
        let mbox_path = mailbox_path.clone();
        main_window.on_ingest_reply_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let hex_str = ui.get_ingest_raw_hex().trim().to_string();
                if hex_str.is_empty() {
                    ui.set_status_log("Enter the hex string of the ReplicaReadReply envelope to decrypt.".into());
                    return;
                }

                let raw_bytes = match hex::decode(&hex_str) {
                    Ok(b) => b,
                    Err(e) => {
                        ui.set_status_log(format!("Hex decoding error: {}", e).into());
                        return;
                    }
                };

                let reply = match ReplicaReadReply::decode(&raw_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        ui.set_status_log(format!("ReplicaReadReply decoding error: {}", e).into());
                        return;
                    }
                };

                let mut mbox_guard = mbox_rc.borrow_mut();
                let mbox = match mbox_guard.as_mut() {
                    Some(m) => m,
                    None => return,
                };
                match mbox.ingest_reply(&reply) {
                    Ok(plaintext) => {
                        let _ = if let Some(ref p) = *pass_rc.borrow() {
                            mbox.save_with_passphrase(&mbox_path, p)
                        } else {
                            mbox.save(&mbox_path)
                        };
                        reload_ui_models(&ui, mbox);
                        ui.set_ingest_raw_hex("".into());
                        ui.set_selected_message_text(plaintext.clone().into());
                        ui.set_selected_message_info("Envelope decrypted successfully! State: Observed decoherence:".into());
                        ui.set_status_log("Pigeonhole envelope decrypted and committed to mailbox!".into());
                    }
                    Err(e) => {
                        ui.set_status_log(format!("Envelope decryption error: {}", e).into());
                    }
                }
            }
        });
    }

    // Callback add contact
    {
        let mbox_rc = mailbox_ref.clone();
        let pass_rc = passphrase_ref.clone();
        let ui_weak = main_window.as_weak();
        let mbox_path = mailbox_path.clone();
        main_window.on_add_contact_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let username = ui.get_new_contact_username().trim().to_string();
                let box_id = ui.get_new_contact_box_id().trim().to_string();

                if username.is_empty() || box_id.is_empty() {
                    ui.set_status_log("Enter both a username and a 32-byte hex Box ID.".into());
                    return;
                }

                let mut mbox_guard = mbox_rc.borrow_mut();
                let mbox = match mbox_guard.as_mut() {
                    Some(m) => m,
                    None => return,
                };
                match mbox.add_contact(&username, &box_id) {
                    Ok(_) => {
                        let _ = if let Some(ref p) = *pass_rc.borrow() {
                            mbox.save_with_passphrase(&mbox_path, p)
                        } else {
                            mbox.save(&mbox_path)
                        };
                        reload_ui_models(&ui, mbox);
                        ui.set_new_contact_username("".into());
                        ui.set_new_contact_box_id("".into());
                        ui.set_status_log(format!("Contact '{}' added successfully with deterministic identicon generated!", username).into());
                    }
                    Err(e) => {
                        ui.set_status_log(format!("Add contact error: {}", e).into());
                    }
                }
            }
        });
    }

    // Callback use contact as recipient
    {
        let ui_weak = main_window.as_weak();
        main_window.on_use_contact_clicked(move |box_id| {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_recipient_box_id(box_id.clone());
                ui.set_active_tab(0); // Switch to Composer
                ui.set_status_log(format!("Recipient set to {}.", &box_id[0..12.min(box_id.len())]).into());
            }
        });
    }

    main_window.run().map_err(|e| format!("Slint GUI runtime error: {}", e))?;
    Ok(())
}

/// Fallback / Headless Interactive TUI Mode
pub fn run_interactive_tui() -> Result<(), String> {
    let mailbox_path = default_vault_mailbox_path();
    let mut mailbox = VaultMailbox::new_or_load(&mailbox_path)
        .map_err(|e| format!("Mailbox initialization error: {}", e))?;

    let mut kbd = VirtualKeyboardState::new();

    loop {
        println!("\n================================================================================");
        println!("     KATZENPOST SOVEREIGN VAULT — AIR-GAPPED SOVEREIGNTY & PIGEONHOLE          ");
        println!("================================================================================");
        println!("Sovereign Operator    : {}", mailbox.identity.username);
        println!("Box ID Identity       : {}", mailbox.identity.box_id_hex);
        println!("Identicon Avatar (Deterministic cryptographic profile):");
        println!("{}", mailbox.identity.identicon().render_terminal());
        println!("--------------------------------------------------------------------------------");
        println!("Messages in Mailbox   : {}", mailbox.messages.len());
        println!("Contacts in Addressbook: {}", mailbox.contacts.len());
        println!("--------------------------------------------------------------------------------");
        println!("Menu:");
        println!("  1. Compose & deposit message (with partitioned anti-keylogger virtual keyboard)");
        println!("  2. View Mailbox messages (Schrödinger Quantum State)");
        println!("  3. View contacts & deterministic identicon avatars");
        println!("  4. Add new contact");
        println!("  5. Exit");
        print!("\nSelection [1-5]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).map_err(|e| e.to_string())?;

        match choice.trim() {
            "1" => {
                let score = kbd.compute_secrecy_score();
                println!("\nInput method: {}", score.shielding_level);
                println!("Use the optional on-screen keyboard?");
                print!("[y/N]: ");
                io::stdout().flush().map_err(|e| e.to_string())?;

                let mut kbd_choice = String::new();
                io::stdin().read_line(&mut kbd_choice).map_err(|e| e.to_string())?;
                let use_v = kbd_choice.trim().eq_ignore_ascii_case("y") || kbd_choice.trim().eq_ignore_ascii_case("s");

                if use_v {
                    kbd.is_enabled = true;
                    kbd.used_for_composition = true;
                    let boosted = kbd.compute_secrecy_score();
                    println!("[i] {}", boosted.shielding_level);
                }

                print!("\nEnter recipient Box ID (or press Enter for loopback self-deposit): ");
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut target = String::new();
                io::stdin().read_line(&mut target).map_err(|e| e.to_string())?;
                let target = target.trim();
                let target_id = if target.is_empty() {
                    mailbox.identity.box_id_hex.clone()
                } else {
                    target.to_string()
                };

                print!("Enter message body: ");
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut msg = String::new();
                io::stdin().read_line(&mut msg).map_err(|e| e.to_string())?;
                let msg = msg.trim();

                let final_score = kbd.compute_secrecy_score();
                let method = if use_v { "Virtual Keyboard (Partitioned Anti-Keylogger)" } else { "Physical Keyboard" };

                let deposit = mailbox.deposit_draft(&target_id, msg, final_score.stars, method)?;
                mailbox.save(&mailbox_path)?;

                println!("[✓] Draft encrypted and deposited successfully!");
                println!("    Size: {} bytes", deposit.payload.len());
                println!("    Quantum state: Superposition (Schrödinger vault sealed)");
            }

            "2" => {
                println!("\n--- VAULT MESSAGE ARCHIVE ({}) ---", mailbox.messages.len());
                if mailbox.messages.is_empty() {
                    println!("No messages present.");
                } else {
                    for (i, m) in mailbox.messages.iter().enumerate() {
                        let dir = match m.direction {
                            MessageDirection::Inbound => "INBOUND [↓]",
                            MessageDirection::Outbound => "OUTBOUND [↑]",
                        };
                        println!("#{} {} | {} | {} stars | State: {}", i + 1, dir, m.id, m.secrecy_stars, m.quantum_state);
                        println!("   Body: {}", m.plaintext);
                    }
                }
            }

            "3" => {
                println!("\n--- SOVEREIGN CONTACTS ({}) ---", mailbox.contacts.len());
                if mailbox.contacts.is_empty() {
                    println!("No contacts saved.");
                } else {
                    for (i, c) in mailbox.contacts.iter().enumerate() {
                        println!("#{} Contact: {} (Box ID: {})", i + 1, c.username, c.box_id_hex);
                        println!("{}", c.identicon().render_terminal());
                    }
                }
            }

            "4" => {
                print!("\nNew contact username: ");
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut u = String::new();
                io::stdin().read_line(&mut u).map_err(|e| e.to_string())?;

                print!("Box ID (64 hex characters): ");
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut b = String::new();
                io::stdin().read_line(&mut b).map_err(|e| e.to_string())?;

                match mailbox.add_contact(u.trim(), b.trim()) {
                    Ok(c) => {
                        mailbox.save(&mailbox_path)?;
                        println!("[✓] Contact added successfully! Deterministic identicon avatar:");
                        println!("{}", c.identicon().render_terminal());
                    }
                    Err(e) => {
                        println!("[!] Error: {}", e);
                    }
                }
            }

            "5" => {
                println!("Exiting Sovereign Vault. Goodbye!");
                break;
            }

            _ => {
                println!("Invalid option.");
            }
        }
    }

    Ok(())
}
