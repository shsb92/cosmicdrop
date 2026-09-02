// SPDX-License-Identifier: GPL-3.0-or-later

mod app;
mod client;
mod config;
mod server;
mod util;

pub const APP_ID: &str = "dev.cosmicdrop.CosmicDrop";

fn main() -> cosmic::iced::Result {
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "warn")
        .write_style_or("RUST_LOG_STYLE", "always");

    env_logger::init_from_env(env);
    cosmic::applet::run::<app::Window>(())
}
