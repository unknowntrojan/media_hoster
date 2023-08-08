#![allow(dead_code)]
#![feature(let_chains)]
#![feature(is_some_and)]
#![feature(async_closure)]

use actix_web::{middleware::Logger, web, App, HttpServer};
use log::debug;
use sqlx::sqlite::SqlitePoolOptions;

mod auth;
mod media;
mod model;
mod panel;
mod users;
mod util;
mod validation;

/// TODO:
///
/// error messages in the login and registration forms
/// fixup the compression thingy in the db so that we take the original blob until we have the compressed one, at which point we will kill the original blob and force usage of the compressed one.
///

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let domain = if let Ok(domain) = std::env::var("DOMAIN") {
        format!("https://{domain}")
    } else {
        format!("http://localhost:80")
    };

    let pool_options = SqlitePoolOptions::new();

    let sql = pool_options
        .connect("sqlite://db.sqlite?mode=rwc")
        .await
        .unwrap();

    sqlx::migrate!("./migrations")
        .run(&sql)
        .await
        .expect("Migrations failed");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::new(
                "%a \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\" %T",
            ))
            .app_data(web::Data::new(sql.clone()))
            .app_data(web::Data::new(domain.clone()))
            .configure(users::configure)
            .configure(panel::configure)
            .configure(media::configure)
    })
    .bind(("0.0.0.0", 80))?
    .run()
    .await
}
