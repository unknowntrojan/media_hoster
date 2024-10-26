use actix_web::{
    body::MessageBody,
    cookie::{Cookie, SameSite},
    get, http, post,
    web::{self, Bytes},
    HttpResponse, Responder,
};
use futures_util::TryStreamExt;
use log::error;
use serde::{Deserialize, Serialize};
use sqlx::{Either, Pool, Sqlite};

use crate::{
    auth::{self, Session},
    model::{Invite, User},
    util, validation,
};

// #[get("/list")]
// async fn list(sql: web::Data<Pool<Sqlite>>) -> impl Responder {
//     let users: Vec<User> = if let Ok(x) = sqlx::query_as!(User, "SELECT * FROM users")
//         .fetch_all(&**sql)
//         .await
//     {
//         x
//     } else {
//         return HttpResponse::InternalServerError().finish();
//     };
//     HttpResponse::Ok().body(format!("{:?}", users))
// }

#[derive(Deserialize, Debug)]
struct LoginForm {
    pub username: String,
    pub password: String,
}

#[post("/login")]
async fn login(
    form: web::Form<LoginForm>,
    sql: web::Data<Pool<Sqlite>>,
    session: Option<Session>,
) -> impl Responder {
    if session.is_some() {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .finish();
    }

    let user = if let Ok(x) = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = ?",
        form.username
    )
    .fetch_one(&**sql)
    .await
    {
        x
    } else {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/login"))
            .cookie(
                Cookie::build("msg", "user not found")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish();
    };

    let token = util::generate_token();

    if let Ok(_) = auth::verify_password(form.password.as_str(), user.password.as_str())
        && let Ok(_) = sqlx::query!(
            "INSERT INTO sessions (user, token) VALUES(?, ?)",
            user.id,
            token
        )
        .execute(&**sql)
        .await
    {
        HttpResponse::Found()
            .cookie(
                Cookie::build("token", token)
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .append_header((http::header::LOCATION, "/"))
            .finish()
    } else {
        // Unauthorized
        HttpResponse::Found()
            .append_header((http::header::LOCATION, "/login"))
            .cookie(
                Cookie::build("msg", "login failed")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish()
    }
}

#[post("/invite")]
async fn generate_invite(sql: web::Data<Pool<Sqlite>>, session: Session) -> impl Responder {
    if session.user.id != 1 {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .cookie(
                Cookie::build("msg", "you are not allowed to create an invite")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish();
    }

    let invite = crate::util::generate_invite();

    match sqlx::query!("INSERT INTO invites (token) VALUES(?)", invite)
        .execute(&**sql)
        .await
    {
        Ok(_) => HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .cookie(
                Cookie::build("msg", invite)
                    .path("/")
                    .secure(true)
                    .same_site(SameSite::Strict)
                    .http_only(true)
                    .finish(),
            )
            .finish(),
        Err(_) => HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .cookie(
                Cookie::build("msg", "failed to create invite")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish(),
    }
}

#[derive(Deserialize)]
struct RegistrationForm {
    username: String,
    password: String,
    invite: String,
}

#[post("/register")]
async fn register(
    form: web::Form<RegistrationForm>,
    sql: web::Data<Pool<Sqlite>>,
    session: Option<Session>,
) -> impl Responder {
    if session.is_some() {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .finish();
    }

    match validation::username(form.username.as_str()) {
        Ok(_) => {}
        Err(x) => {
            return HttpResponse::Found()
                .append_header((http::header::LOCATION, "/register"))
                .cookie(
                    Cookie::build("msg", x)
                        .path("/")
                        .secure(true)
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .finish();
        }
    }

    match validation::password(form.password.as_str()) {
        Ok(_) => {}
        Err(x) => {
            return HttpResponse::Found()
                .append_header((http::header::LOCATION, "/register"))
                .cookie(
                    Cookie::build("msg", x)
                        .path("/")
                        .secure(true)
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .finish();
        }
    }

    let invite = sqlx::query_as!(
        Invite,
        "SELECT * FROM invites WHERE token = ? AND invited IS NULL",
        form.invite
    )
    .fetch_one(&**sql)
    .await;

    let invite = if let Ok(x) = invite {
        x
    } else {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/register"))
            .cookie(
                Cookie::build("msg", "invalid invite")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish();
    };

    let token = util::generate_token();

    let hash = if let Ok(x) = auth::hash_password(form.password.as_str()) {
        x
    } else {
        return HttpResponse::InternalServerError().finish();
    };

    if sqlx::query!(
        "INSERT INTO users (username, password, apikey) VALUES(?, ?, ?)",
        form.username,
        hash,
        token
    )
    .execute(&**sql)
    .await
    .is_err()
    {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/register"))
            .cookie(
                Cookie::build("msg", "internal server error")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish();
    }

    if sqlx::query!(
        "UPDATE invites SET invited = (SELECT id FROM users WHERE username = ?) WHERE id = ?",
        form.username,
        invite.id
    )
    .execute(&**sql)
    .await
    .is_err()
    {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/register"))
            .cookie(
                Cookie::build("msg", "internal server error")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish();
    }

    HttpResponse::Found()
        .append_header((http::header::LOCATION, "/login"))
        .cookie(
            Cookie::build("msg", "registration successful")
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .finish()
}

#[post("/invalidate_apikey")]
async fn invalidate_apikey(session: Session, sql: web::Data<Pool<Sqlite>>) -> impl Responder {
    let token = util::generate_token();

    if sqlx::query!(
        "UPDATE users SET apikey = ? WHERE id = ?",
        token,
        session.user.id
    )
    .execute(&**sql)
    .await
    .is_err()
    {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .cookie(
                Cookie::build("msg", "internal server error")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish();
    }

    HttpResponse::Found()
        .append_header((http::header::LOCATION, "/"))
        .finish()
}

#[post("/download_dump")]
async fn download_dump(session: Session, sql: web::Data<Pool<Sqlite>>) -> impl Responder {
    let uid = session.user.id;

    struct MediaQuery {
        file: Vec<u8>,
        filename: String,
        mime: String,
        added: i64,
    }

    let mut stream = sqlx::query_as!(
        MediaQuery,
        "SELECT file, filename, mime, added FROM media WHERE owner = ?",
        uid
    )
    .fetch(&**sql);

    // let tmp_path = format!("/tmp/{uid}");
    // let archive_path = format!("/tmp/{uid}.tar");
    #[cfg(target_os = "windows")]
    let path = "C:/temp";
    #[cfg(target_os = "linux")]
    let path = "/tmp";

    let tmp_path = format!("{path}/{uid}");
    let archive_path = format!("{path}/{uid}.tar");

    let _ = tokio::fs::remove_dir_all(&tmp_path).await;

    let _ = tokio::fs::remove_file(&archive_path).await;

    // we now have all the files. this is stupid.
    tokio::fs::create_dir_all(&tmp_path)
        .await
        .expect("unable to create user dir");

    while let Ok(Some(media)) = stream.try_next().await {
        let file_path = format!("{tmp_path}/{}", &media.filename);

        if let Err(err) = tokio::fs::write(&file_path, media.file).await {
            error!("failed to write tmp file: {err:?}");
            continue;
        }

        if let Err(err) = filetime::set_file_mtime(
            &file_path,
            filetime::FileTime::from_unix_time(media.added, 0),
        ) {
            error!("failed to set tmp file mtime: {err:?}");
        }
    }

    tar::Builder::new(std::fs::File::create(&archive_path).expect("unable to create archive.tar"))
        .append_dir_all("dump", &tmp_path)
        .expect("unable to archive tar");

    tokio::fs::remove_dir_all(&tmp_path)
        .await
        .expect("unable to remove temporary media dump!");

    scopeguard::defer! {
        std::fs::remove_file(&archive_path).expect("unable to remove archive");
    }

    HttpResponse::Ok()
        .append_header((
            "Content-Disposition",
            "attachment; filename=\"dump.tar.zst\"",
        ))
        .body(
            zstd::encode_all(
                std::fs::File::open(&archive_path).expect("unable to open archive.tar"),
                8,
            )
            .expect("unable to compress")
            .try_into_bytes()
            .unwrap(),
        )
}

#[get("/uploader")]
async fn sharex_uploader(domain: web::Data<String>, session: Session) -> impl Responder {
    // generate a SXCU file.

    #[derive(Serialize)]
    struct UploaderSxcu {
        #[serde(rename = "Version")]
        version: String,
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "FileFormName")]
        file_form_name: String,
        #[serde(rename = "DestinationType")]
        destination_type: String,
        #[serde(rename = "RequestMethod")]
        request_method: String,
        #[serde(rename = "RequestURL")]
        request_url: String,
        #[serde(rename = "Body")]
        body: String,
        #[serde(rename = "URL")]
        url: String,
        #[serde(rename = "ErrorMessage")]
        error_msg: String,
    }

    let sxcu = UploaderSxcu {
        version: "15.0.0".into(),
        name: "Chloride Uploader".into(),
        file_form_name: "unknown".into(),
        destination_type: "ImageUploader, FileUploader".into(),
        request_method: "POST".into(),
        request_url: format!("{}/upload?key={}", domain.as_str(), session.user.apikey),
        body: "MultipartFormData".into(),
        url: "{json:url}".into(),
        error_msg: "{json:error}".into(),
    };

    HttpResponse::Ok()
        .append_header((
            "Content-Disposition",
            "attachment; filename=chloride_uploader.sxcu",
        ))
        .json(sxcu)
}

#[get("/shortener")]
async fn sharex_shortener(domain: web::Data<String>, session: Session) -> impl Responder {
    // generate a SXCU file.

    #[derive(Serialize)]
    struct Parameters {
        url: String,
        text: String,
        key: String,
    }

    #[derive(Serialize)]
    struct ShortenerSxcu {
        #[serde(rename = "Version")]
        version: String,
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "DestinationType")]
        destination_type: String,
        #[serde(rename = "RequestMethod")]
        request_method: String,
        #[serde(rename = "RequestURL")]
        request_url: String,
        #[serde(rename = "URL")]
        url: String,
        #[serde(rename = "Parameters")]
        parameters: Parameters,
    }

    let sxcu = ShortenerSxcu {
        version: "15.0.0".into(),
        name: "Chloride Shortener".into(),
        destination_type: "URLShortener".into(),
        request_method: "POST".into(),
        request_url: format!("{}/shorten", domain.as_str()),
        parameters: Parameters {
            url: "{input}".into(),
            text: "i am a furry".into(),
            key: session.user.apikey,
        },
        url: "{response}".into(),
    };

    HttpResponse::Ok()
        .append_header((
            "Content-Disposition",
            "attachment; filename=chloride_shortener.sxcu",
        ))
        .json(sxcu)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    let scope = web::scope("/users")
        // .service(list)
        .service(sharex_uploader)
        .service(sharex_shortener)
        .service(login)
        .service(register)
        .service(invalidate_apikey)
        .service(download_dump)
        .service(generate_invite);

    cfg.service(scope);
}
