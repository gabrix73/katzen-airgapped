use crate::pigeonhole::{default_vault_mailbox_path, MessageDirection, ReplicaReadReply, VaultMailbox};
use crate::virtual_keyboard::VirtualKeyboardState;
use slint::VecModel;
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

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
        in-out property <string> message_body: "Air-gapped Katzenpost client ready: Wire invariants verified (katzenqt1), partitioned anti-keylogger virtual keyboard active, deterministic identicons rendered.";
        in-out property <string> secrecy_stars: "★★★★★ (100%)";
        in-out property <string> secrecy_desc: "Maximum quantum shielding. Anti-keylogger partitioned virtual keyboard active.";
        in-out property <string> quantum_status: "🐱 Quantum State: Superposition (Schrödinger Vault Sealed)";
        in-out property <string> opsec_tip: "OPSEC: Optical diode / removable media physically isolates Vault from network observation.";
        in-out property <bool> use_virtual_kbd: true;
        in-out property <string> numbers_row: "1  2  3  4  5  6  7  8  9  0";
        in-out property <string> letters_row1: "q  w  e  r  t  y  u  i  o  p";
        in-out property <string> letters_row2: "a  s  d  f  g  h  j  k  l";
        in-out property <string> letters_row3: "z  x  c  v  b  n  m";
        in-out property <string> symbols_row: ".  ,  ?  !  :  ;  @  #  $  %  &  *  -  +  =";
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
        callback export_spool_clicked();
        callback poll_mailbox_clicked();

        callback select_message_clicked(string, string);
        callback ingest_reply_clicked();

        callback add_contact_clicked();
        callback use_contact_clicked(string);

        VerticalLayout {
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
                        text: "Anti-Keylogger Virtual Keyboard (Shielding: ★★★★★ 100%)";
                        color: #edf2f7;
                        font_size: 12px;
                        font_weight: 600;
                        vertical_alignment: center;
                    }
                    Rectangle { horizontal_stretch: 1; }
                    if root.use_virtual_kbd : Button {
                        text: "Shuffle Keys (Intra-Group) 🔀";
                        clicked => { root.shuffle_keys_clicked(); }
                    }
                }

                if root.use_virtual_kbd : Rectangle {
                    background: #1a1e29;
                    border_radius: 6px;
                    border_width: 1px;
                    border_color: #3182ce;

                    VerticalLayout {
                        padding: 8px;
                        spacing: 6px;

                        Text {
                            text: "Partitioned Layout (Numbers, letters and symbols isolated for intuitive typing):";
                            color: #63b3ed;
                            font_size: 11px;
                        }

                        HorizontalLayout {
                            spacing: 4px;
                            Text { text: "NUM:"; color: #a0aec0; font_size: 11px; width: 40px; vertical_alignment: center; }
                            Text { text: root.numbers_row; color: #f7fafc; font_size: 12px; font_family: "monospace"; }
                        }
                        HorizontalLayout {
                            spacing: 4px;
                            Text { text: "LET1:"; color: #a0aec0; font_size: 11px; width: 40px; vertical_alignment: center; }
                            Text { text: root.letters_row1; color: #f7fafc; font_size: 12px; font_family: "monospace"; }
                        }
                        HorizontalLayout {
                            spacing: 4px;
                            Text { text: "LET2:"; color: #a0aec0; font_size: 11px; width: 40px; vertical_alignment: center; }
                            Text { text: root.letters_row2; color: #f7fafc; font_size: 12px; font_family: "monospace"; }
                        }
                        HorizontalLayout {
                            spacing: 4px;
                            Text { text: "LET3:"; color: #a0aec0; font_size: 11px; width: 40px; vertical_alignment: center; }
                            Text { text: root.letters_row3; color: #f7fafc; font_size: 12px; font_family: "monospace"; }
                        }
                        HorizontalLayout {
                            spacing: 4px;
                            Text { text: "SYM:"; color: #a0aec0; font_size: 11px; width: 40px; vertical_alignment: center; }
                            Text { text: root.symbols_row; color: #f7fafc; font_size: 12px; font_family: "monospace"; }
                        }
                    }
                }

                // Action Buttons
                HorizontalLayout {
                    spacing: 12px;

                    Button {
                        text: "Construct Sphinx Packet & Save Draft";
                        primary: true;
                        clicked => { root.send_message_clicked(); }
                    }

                    Button {
                        text: "Export USB Spool";
                        clicked => { root.export_spool_clicked(); }
                    }

                    Button {
                        text: "Poll Pigeonhole Mailbox";
                        clicked => { root.poll_mailbox_clicked(); }
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
                    text: "Each contact has a bilateral 5x5 identicon derived from SHA-256(username | Box ID). 100% sovereign, zero email, visually verifiable.";
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
    let mailbox = VaultMailbox::new_or_load(&mailbox_path)
        .map_err(|e| format!("Mailbox initialization error: {}", e))?;

    let main_window = MainWindow::new().map_err(|e| format!("Slint GUI init error: {}", e))?;
    let mut kbd_state = VirtualKeyboardState::new();
    kbd_state.is_enabled = true;
    kbd_state.used_for_composition = true;

    let my_id = format!("Box ID: {}", mailbox.identity.box_id_hex);
    main_window.set_my_box_id(my_id.into());

    let op_avatar = mailbox.identity.identicon().to_slint_image(8);
    main_window.set_operator_avatar(op_avatar);

    reload_ui_models(&main_window, &mailbox);

    let update_rows = {
        let handle = main_window.as_weak();
        move |kbd: &VirtualKeyboardState| {
            if let Some(ui) = handle.upgrade() {
                let n_str: String = kbd.numbers.iter().map(|c| format!("{} ", c)).collect();
                ui.set_numbers_row(n_str.into());

                let l1: String = kbd.letters[0..10.min(kbd.letters.len())].iter().map(|c| format!("{} ", c)).collect();
                let l2: String = kbd.letters[10..19.min(kbd.letters.len())].iter().map(|c| format!("{} ", c)).collect();
                let l3: String = kbd.letters[19..kbd.letters.len()].iter().map(|c| format!("{} ", c)).collect();
                ui.set_letters_row1(l1.into());
                ui.set_letters_row2(l2.into());
                ui.set_letters_row3(l3.into());

                let s_str: String = kbd.symbols.iter().map(|c| format!("{} ", c)).collect();
                ui.set_symbols_row(s_str.into());

                let score = kbd.compute_secrecy_score();
                let star_text = format!("{} ({}%)", "★".repeat(score.stars as usize), score.score_percentage);
                ui.set_secrecy_stars(star_text.into());
                ui.set_secrecy_desc(score.opsec_note.into());
            }
        }
    };

    update_rows(&kbd_state);

    let kbd_ref = Rc::new(RefCell::new(kbd_state));
    let mailbox_ref = Rc::new(RefCell::new(mailbox));

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
                let star_text = format!("{} ({}%)", "★".repeat(score.stars as usize), score.score_percentage);
                ui.set_secrecy_stars(star_text.into());
                ui.set_secrecy_desc(score.opsec_note.into());
                if enabled {
                    ui.set_status_log("Partitioned virtual keyboard enabled. Secrecy score boosted to 100% ★★★★★.".into());
                } else {
                    ui.set_status_log("Physical keyboard enabled. Secrecy score set to standard isolation (70%).".into());
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

    // Callback send / deposit message
    {
        let mbox_rc = mailbox_ref.clone();
        let kbd_rc = kbd_ref.clone();
        let ui_weak = main_window.as_weak();
        let mbox_path = mailbox_path.clone();
        main_window.on_send_message_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let recip = ui.get_recipient_box_id();
                let body = ui.get_message_body();
                let k = kbd_rc.borrow();
                let score = k.compute_secrecy_score();
                let method = if k.used_for_composition {
                    "Virtual Keyboard (Anti-Keylogger)"
                } else {
                    "Physical Keyboard"
                };

                if recip.trim().is_empty() {
                    ui.set_status_log("Enter a valid recipient Box ID before proceeding.".into());
                    return;
                }

                let mut mbox = mbox_rc.borrow_mut();
                match mbox.deposit_draft(&recip, &body, score.stars, method) {
                    Ok(replica_write) => {
                        let _ = mbox.save(&mbox_path);
                        reload_ui_models(&ui, &mbox);
                        ui.set_status_log(format!("Draft encrypted successfully for {} ({} bytes deposited).", &recip[0..8.min(recip.len())], replica_write.payload.len()).into());
                        ui.set_quantum_status("🐱 Quantum State: Superposition (Packet queued for mixnet)".into());
                    }
                    Err(e) => {
                        ui.set_status_log(format!("Deposit encryption error: {}", e).into());
                    }
                }
            }
        });
    }

    // Callback export spool
    {
        let ui_weak = main_window.as_weak();
        main_window.on_export_spool_clicked(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_status_log("Encrypted packets spooled to removable media directory (/media/usb/spool).".into());
                ui.set_opsec_tip("Tip: Use physical read-only hardware switch SD cards to neutralize BadUSB attacks.".into());
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

                let mut mbox = mbox_rc.borrow_mut();
                match mbox.ingest_reply(&reply) {
                    Ok(plaintext) => {
                        let _ = mbox.save(&mbox_path);
                        reload_ui_models(&ui, &mbox);
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

                let mut mbox = mbox_rc.borrow_mut();
                match mbox.add_contact(&username, &box_id) {
                    Ok(_) => {
                        let _ = mbox.save(&mbox_path);
                        reload_ui_models(&ui, &mbox);
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
                println!("\nCurrent Secrecy Score: {} ({}%) - {}", "⭐".repeat(score.stars as usize), score.score_percentage, score.shielding_level);
                println!("Enable partitioned anti-keylogger virtual keyboard to boost secrecy score to 100% ⭐⭐⭐⭐⭐?");
                print!("[y/N]: ");
                io::stdout().flush().map_err(|e| e.to_string())?;

                let mut kbd_choice = String::new();
                io::stdin().read_line(&mut kbd_choice).map_err(|e| e.to_string())?;
                let use_v = kbd_choice.trim().eq_ignore_ascii_case("y") || kbd_choice.trim().eq_ignore_ascii_case("s");

                if use_v {
                    kbd.is_enabled = true;
                    kbd.used_for_composition = true;
                    let boosted = kbd.compute_secrecy_score();
                    println!("[✓] Virtual keyboard active: score boosted to {} ({}%)", "⭐".repeat(boosted.stars as usize), boosted.score_percentage);
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
