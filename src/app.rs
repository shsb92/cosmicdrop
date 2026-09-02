// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;
use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender};

use cosmic::app::{Core, Task};
use cosmic::iced::core::window;
use cosmic::iced::window::Id;
use cosmic::iced::{Alignment, Length, Limits, Rectangle, Subscription};
use cosmic::surface::action::{app_popup, destroy_popup};
use cosmic::widget::list::{button as list_button, list_column};
use cosmic::widget::{button, column, row, scrollable, text, text_input};
use cosmic::{Action, Application, Element};

use crate::client::{AirDropBrowser, AirDropClient, BrowserEvent, Receiver as AirDropReceiver};
use crate::config::AirDropConfig;
use crate::server::{AirDropServer, ServerEvent};
use crate::APP_ID;

/// Which section of the popup is currently shown.
#[derive(Default, Clone, Copy, PartialEq, Debug)]
pub enum Page {
    #[default]
    Send,
    Receive,
}

impl Page {
    const ALL: [Page; 2] = [Page::Send, Page::Receive];

    fn label(self) -> &'static str {
        match self {
            Page::Send => "Send",
            Page::Receive => "Receive",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    PopupClosed(Id),
    Surface(cosmic::surface::Action),
    Page(Page),
    SetSelectedReceiver(String),
    PickFile,
    SendFile,
    ToggleReceive,
    ApplySettings,
    SetComputerName(String),
    SetModel(String),
    SetInterface(String),
    ScrollSend,
    Tick,
}

pub struct Window {
    core: Core,
    popup: Option<Id>,
    page: Page,

    config: AirDropConfig,

    // Send
    browser_stop: Option<MpscSender<()>>,
    browser_rx: Option<MpscReceiver<BrowserEvent>>,
    receivers: Vec<AirDropReceiver>,
    selected_receiver: Option<String>,
    selected_file: Option<PathBuf>,
    send_rx: Option<MpscReceiver<String>>,
    send_messages: Vec<String>,

    // Receive
    server_stop: Option<MpscSender<()>>,
    server_rx: Option<MpscReceiver<ServerEvent>>,
    server_running: bool,
    receive_messages: Vec<String>,

    // Settings
    settings_name: String,
    settings_model: String,
    settings_interface: String,
}

impl Default for Window {
    fn default() -> Self {
        let config = AirDropConfig::new(None, None, None, None, None, None, None, None, false, None)
            .unwrap_or_else(|e| {
                eprintln!("failed to read config: {e}");
                unreachable!()
            });
        let settings_name = config.computer_name.clone();
        let settings_model = config.computer_model.clone();
        let settings_interface = config.interface.clone();
        Self {
            core: Core::default(),
            popup: None,
            page: Page::default(),
            config,
            browser_stop: None,
            browser_rx: None,
            receivers: Vec::new(),
            selected_receiver: None,
            selected_file: None,
            send_rx: None,
            send_messages: Vec::new(),
            server_stop: None,
            server_rx: None,
            server_running: false,
            receive_messages: Vec::new(),
            settings_name,
            settings_model,
            settings_interface,
        }
    }
}

impl Application for Window {
    type Executor = cosmic::SingleThreadExecutor;
    type Flags = ();
    type Message = Message;
    const APP_ID: &'static str = APP_ID;

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Message>) {
        let window = Window {
            core,
            ..Default::default()
        };
        (window, Task::none())
    }

    fn on_close_requested(&self, id: window::Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PopupClosed(id) => {
                if self.popup.as_ref() == Some(&id) {
                    self.popup = None;
                }
                self.stop_discovery();
                Task::none()
            }
            Message::Surface(a) => {
                return cosmic::task::message(Action::Cosmic(cosmic::app::Action::Surface(a)));
            }
            Message::Page(page) => {
                self.page = page;
                if page == Page::Send && self.browser_rx.is_none() {
                    self.start_discovery();
                }
                Task::none()
            }
            Message::SetSelectedReceiver(id) => {
                self.selected_receiver = Some(id);
                Task::none()
            }
            Message::PickFile => {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.selected_file = Some(path);
                }
                Task::none()
            }
            Message::SendFile => self.begin_send(),
            Message::ToggleReceive => {
                if self.server_running {
                    self.stop_server();
                } else {
                    self.start_server();
                }
                Task::none()
            }
            Message::ApplySettings => {
                self.config.computer_name = self.settings_name.clone();
                self.config.computer_model = self.settings_model.clone();
                self.config.interface = self.settings_interface.clone();
                Task::none()
            }
            Message::SetComputerName(v) => {
                self.settings_name = v;
                Task::none()
            }
            Message::SetModel(v) => {
                self.settings_model = v;
                Task::none()
            }
            Message::SetInterface(v) => {
                self.settings_interface = v;
                Task::none()
            }
            Message::ScrollSend => {
                self.stop_discovery();
                self.start_discovery();
                Task::none()
            }
            Message::Tick => {
                self.drain_background();
                Task::none()
            }
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        cosmic::iced::time::every(std::time::Duration::from_millis(120)).map(|_| Message::Tick)
    }

    fn view(&self) -> Element<'_, Message> {
        let have_popup = self.popup.clone();
        let btn = self
            .core
            .applet
            .icon_button_from_handle(cosmic::widget::icon::from_svg_bytes(
                include_bytes!("../res/icons/dev.cosmicdrop.CosmicDrop.svg").as_slice(),
            ))
            .on_press_with_rectangle(move |offset, bounds| {
                if let Some(id) = have_popup {
                    Message::Surface(destroy_popup(id))
                } else {
                    Message::Surface(app_popup::<Window>(
                        |_| Default::default(),
                        move |state: &mut Window| {
                            let new_id = Id::unique();
                            state.popup = Some(new_id);
                            let mut popup_settings = state.core.applet.get_popup_settings(
                                state.core.main_window_id().unwrap(),
                                new_id,
                                None,
                                None,
                                None,
                            );
                            popup_settings.positioner.anchor_rect = Rectangle {
                                x: (bounds.x - offset.x) as i32,
                                y: (bounds.y - offset.y) as i32,
                                width: bounds.width as i32,
                                height: bounds.height as i32,
                            };
                            popup_settings.positioner.size_limits = Limits::NONE
                                .max_width(480.0)
                                .min_width(360.0)
                                .min_height(300.0)
                                .max_height(1080.0);
                            popup_settings
                        },
                        Some(Box::new(move |state: &Window| {
                            let content = state.view_content();
                            Element::from(state.core.applet.popup_container(content))
                                .map(cosmic::Action::App)
                        })),
                    ))
                }
            });

        Element::from(self.core.applet.applet_tooltip::<Message>(
            btn,
            "CosmicDrop",
            self.popup.is_some(),
            Message::Surface,
            None,
        ))
    }

    fn view_window(&self, _id: Id) -> Element<'_, Message> {
        "CosmicDrop".into()
    }

    fn style(&self) -> Option<cosmic::iced::theme::Style> {
        Some(cosmic::applet::style())
    }
}

impl Window {
    fn drain_background(&mut self) {
        if let Some(rx) = &self.send_rx {
            while let Ok(line) = rx.try_recv() {
                self.send_messages.push(line);
            }
        }
        if let Some(rx) = &self.browser_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    BrowserEvent::Found(receiver) => {
                        if let Some(existing) =
                            self.receivers.iter_mut().find(|r| r.id == receiver.id)
                        {
                            *existing = receiver;
                        } else {
                            self.receivers.push(receiver);
                        }
                    }
                    BrowserEvent::Removed(id) => {
                        self.receivers.retain(|r| r.id != id);
                    }
                }
            }
        }
        if let Some(rx) = &self.server_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    ServerEvent::Ask {
                        sender_name,
                        file_name,
                        ..
                    } => self.receive_messages.push(format!(
                        "Ask: {sender_name} wants to send {file_name}"
                    )),
                    ServerEvent::Accepted => self.receive_messages.push("Accepted.".into()),
                    ServerEvent::Received { file_name } => {
                        self.receive_messages.push(format!("Saved: {file_name}"))
                    }
                    ServerEvent::Error(e) => {
                        self.receive_messages.push(format!("Error: {e}"))
                    }
                    other => self.receive_messages.push(format!("Event: {other:?}")),
                }
            }
        }
    }

    fn view_content(&self) -> Element<'_, Message> {
        let mut content = column(vec![
            row(vec![
                text("CosmicDrop").size(20).into(),
                text(format!(":{}", self.config.port)).size(12).into(),
            ])
            .align_y(Alignment::Center)
            .spacing(8)
            .into(),
            self.view_nav().into(),
            match self.page {
                Page::Send => self.view_send().into(),
                Page::Receive => self.view_receive().into(),
            },
        ])
        .spacing(12)
        .padding(16);

        if self.page == Page::Receive {
            content = content.push(self.view_settings());
        }

        content.into()
    }

    fn view_nav(&self) -> Element<'_, Message> {
        let mut nav = row(Vec::new()).spacing(8);
        for page in Page::ALL {
            let selected = self.page == page;
            let mut btn = button::text(page.label());
            if !selected {
                btn = btn.class(cosmic::widget::button::ButtonClass::Transparent);
            }
            nav = nav.push(btn.on_press(Message::Page(page)));
        }
        nav.into()
    }

    fn view_send(&self) -> Element<'_, Message> {
        let mut devices = list_column();
        if self.receivers.is_empty() {
            devices = devices.add(text(
                format!("{} device(s) in range", self.receivers.len()),
            ));
        } else {
            for receiver in &self.receivers {
                let label = receiver
                    .name
                    .clone()
                    .unwrap_or_else(|| receiver.id.clone());
                let selected = self.selected_receiver.as_deref() == Some(receiver.id.as_str());
                devices = devices.add(
                    list_button(text(format!("{label}  ({})", receiver.hostname)))
                        .on_press(Message::SetSelectedReceiver(receiver.id.clone()))
                        .selected(selected),
                );
            }
        }

        let file_label = self
            .selected_file
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "No file selected".into());

        let mut send_col = column(vec![
            row(vec![
                text(if self.browser_rx.is_some() {
                    "Scanning...".to_string()
                } else {
                    format!("{} device(s)", self.receivers.len())
                })
                .size(13)
                .into(),
                button::text("Rescan")
                    .on_press(Message::ScrollSend)
                    .into(),
            ])
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
            devices.into(),
            row(vec![
                button::text("Choose file").on_press(Message::PickFile).into(),
                text(file_label).size(13).into(),
            ])
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
            button::suggested("Send")
                .on_press(Message::SendFile)
                .width(Length::Fill)
                .into(),
        ])
        .spacing(8);

        if !self.send_messages.is_empty() {
            let log = column(self.send_messages.iter().map(|l| text(l).size(12).into()))
                .spacing(2);
            send_col = send_col.push(scrollable(log).height(Length::Fill));
        }

        send_col.into()
    }

    fn view_receive(&self) -> Element<'_, Message> {
        let status = if self.server_running {
            "● Receiving"
        } else {
            "○ Idle"
        };
        let mut receive_col = column(vec![
            row(vec![
                button::text(if self.server_running {
                    "Stop receiving"
                } else {
                    "Start receiving"
                })
                .on_press(Message::ToggleReceive)
                .into(),
                text(status).into(),
            ])
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
            text(format!("Saving to: {:?}", self.config.airdrop_dir))
                .size(12)
                .into(),
        ])
        .spacing(8);

        let log = column(self.receive_messages.iter().map(|l| text(l).size(12).into()))
            .spacing(2);
        receive_col = receive_col.push(scrollable(log).height(Length::Fill));

        receive_col.into()
    }

    fn view_settings(&self) -> Element<'_, Message> {
        column(vec![
            text_input("Computer name", &self.settings_name)
                .on_input(Message::SetComputerName)
                .into(),
            text_input("Model", &self.settings_model)
                .on_input(Message::SetModel)
                .into(),
            text_input("Interface", &self.settings_interface)
                .on_input(Message::SetInterface)
                .into(),
            button::suggested("Apply")
                .on_press(Message::ApplySettings)
                .width(Length::Fill)
                .into(),
            text(format!("Keys: {}", self.config.key_dir.display()))
                .size(12)
                .into(),
        ])
        .spacing(8)
        .into()
    }

    fn start_discovery(&mut self) {
        match AirDropBrowser::start(&self.config) {
            Ok((browser, stop_tx)) => {
                self.browser_stop = Some(stop_tx);
                self.browser_rx = Some(browser.events);
                self.receivers.clear();
            }
            Err(e) => {
                self.send_messages.push(format!("Discovery error: {e}"));
            }
        }
    }

    fn stop_discovery(&mut self) {
        if let Some(stop) = self.browser_stop.take() {
            let _ = stop.send(());
        }
        self.browser_rx = None;
    }

    fn start_server(&mut self) {
        match AirDropServer::start(&self.config) {
            Ok((server, stop_tx)) => {
                self.server_stop = Some(stop_tx);
                self.server_rx = Some(server.events);
                self.server_running = true;
                self.receive_messages
                    .push(format!("Listening on port {}...", server.port));
            }
            Err(e) => {
                self.receive_messages.push(format!("Failed to start: {e}"));
            }
        }
    }

    fn stop_server(&mut self) {
        if let Some(stop) = self.server_stop.take() {
            let _ = stop.send(());
        }
        self.server_rx = None;
        self.server_running = false;
        self.receive_messages.push("Stopped receiving.".into());
    }

    fn begin_send(&mut self) -> Task<Message> {
        let Some(receiver_id) = self.selected_receiver.clone() else {
            self.send_messages.push("No receiver selected".into());
            return Task::none();
        };
        let Some(file) = self.selected_file.clone() else {
            self.send_messages.push("No file selected".into());
            return Task::none();
        };
        let Some(receiver) = self
            .receivers
            .iter()
            .find(|r| r.id == receiver_id)
            .cloned()
        else {
            self.send_messages.push("Receiver no longer available".into());
            return Task::none();
        };

        let client = AirDropClient::new(&self.config, &receiver);
        self.send_messages
            .push(format!("Sending {} ...", file.display()));

        let (tx, rx) = std::sync::mpsc::channel::<String>();
        self.send_rx = Some(rx);

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(format!("Runtime error: {e}"));
                    return;
                }
            };
            rt.block_on(async move {
                match client.send_ask_async(&file).await {
                    Ok(false) => {
                        let _ = tx.send("Receiver declined.".into());
                    }
                    Err(e) => {
                        let _ = tx.send(format!("Ask error: {e}"));
                    }
                    Ok(true) => match client.send_upload_async(&file).await {
                        Ok(true) => {
                            let _ = tx.send("Upload successful.".into());
                        }
                        Ok(false) => {
                            let _ = tx.send("Upload failed.".into());
                        }
                        Err(e) => {
                            let _ = tx.send(format!("Upload error: {e}"));
                        }
                    },
                }
            });
        });

        Task::none()
    }
}
