use std::error::Error;

use actix_multipart::Multipart;
use actix_web::{
    cookie::{Cookie, SameSite},
    get, guard,
    http::{self, header::ContentType},
    post,
    rt::spawn,
    web::{self},
    HttpRequest, HttpResponse, Responder,
};
use bytesize::ByteSize;
use futures_util::TryStreamExt as _;
use log::{debug, error, info};
use mime::Mime;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

use crate::{auth::Session, model::User, util};

#[get("/{hash}")]
async fn get(
    req: HttpRequest,
    sql: web::Data<Pool<Sqlite>>,
    hash: web::Path<String>,
) -> impl Responder {
    let hash = hash.to_string();

    //util::from_invisible(hash.to_string());
    // let hash = if let Ok(x) = hash {
    //     x
    // } else {
    //     return HttpResponse::BadRequest().finish();
    // };

    // let hash = radix_fmt::radix_36(hash).to_string();

    let useragent = req.headers().get("User-Agent");

    let is_discordbot = if let Some(useragent) = useragent {
        useragent.to_str().unwrap_or("").contains("Discordbot")
    } else {
        false
    };

    struct MediaQuery {
        file: Vec<u8>,
        filename: String,
        mime: String,
    }

    let file: MediaQuery = match is_discordbot {
        true => {
            if let Ok(x) = sqlx::query_as!(
				MediaQuery,
				"SELECT IFNULL(embeddable_file, file) AS \"file!\", filename, mime FROM media WHERE hash = ?",
				hash
			)
            .fetch_one(&**sql)
            .await
            {
                x
            } else {
                debug!("cant find {hash} in db");
                return HttpResponse::NotFound().finish();
            }
        }
        false => {
            match sqlx::query_as!(
                MediaQuery,
                "SELECT file, filename, mime FROM media WHERE hash = ?",
                hash
            )
            .fetch_one(&**sql)
            .await
            {
                Ok(x) => x,
                Err(x) => {
                    debug!("hash: {} {}", hash, x);
                    return HttpResponse::NotFound().finish();
                }
            }
        }
    };

    let mime = file.mime.parse().unwrap_or(mime::APPLICATION_OCTET_STREAM);

    HttpResponse::Ok()
        .append_header((
            "Content-Disposition",
            format!(
                "{}; filename=\"{}\"",
                if mime == mime::APPLICATION_OCTET_STREAM {
                    "attachment"
                } else {
                    "inline"
                },
                file.filename
            ),
        ))
        .content_type(mime)
        .body(file.file)
}

struct FileData {
    data: Vec<u8>,
    filename: String,
    filetype: Mime,
}

async fn receive_file(mut payload: Multipart) -> Result<FileData, Box<dyn Error>> {
    let mut data: Vec<u8> = Default::default();
    let mut filename: String = Default::default();
    let mut filetype: Mime = mime::APPLICATION_OCTET_STREAM;

    while let Some(mut field) = payload.try_next().await? {
        let content_disposition = field.content_disposition();

        filename = content_disposition
            .ok_or("content disposition empty")?
            .get_filename()
            .unwrap_or("unknown")
            .to_owned();

        if let Some(content_type) = field.content_type() {
            filetype = content_type.clone();
        }

        while let Some(chunk) = field.try_next().await? {
            if data.len() > ByteSize::gb(1).as_u64() as usize {
                return Err("file too large".into());
            }

            data.extend(chunk)
        }
    }

    Ok(FileData {
        data,
        filename,
        filetype,
    })
}

#[derive(Deserialize)]
struct Auth {
    key: String,
}

#[post("/upload")]
async fn upload(
    payload: Multipart,
    apikey: web::Query<Auth>,
    sql: web::Data<Pool<Sqlite>>,
    domain: web::Data<String>,
) -> impl Responder {
    #[derive(Serialize)]
    struct ErrorResponse {
        error: String,
    }

    #[derive(Serialize)]
    struct JsonResponse {
        url: String,
    }

    let apikey = apikey.key.clone();

    let user = if let Ok(x) = sqlx::query_as!(User, "SELECT * FROM users WHERE apikey = ?", apikey)
        .fetch_one(&**sql)
        .await
    {
        x
    } else {
        return HttpResponse::Forbidden().json(ErrorResponse {
            error: "Unable to identify user.".into(),
        });
    };

    let filedata = if let Ok(x) = receive_file(payload).await {
        x
    } else {
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "An error has occurred during file transfer.".into(),
        });
    };

    let (_, hash) = util::data_hash(&filedata.data);
    let link_hash = hash.clone(); // util::to_invisible(hash_raw);

    debug!(
        "Upload requested: Hash {}, MIME: {}, FileName: {}",
        &hash, filedata.filetype, filedata.filename
    );

    let filetype = filedata.filetype.to_string();

    match sqlx::query!(
        "INSERT INTO media (hash, mime, owner, filename, file) VALUES (?, ?, ?, ?, ?)",
        hash,
        filetype,
        user.id,
        filedata.filename,
        filedata.data
    )
    .execute(&**sql)
    .await
    {
        Ok(_) => {}
        Err(x) => {
            if let sqlx::Error::Database(x) = x
                && let Some(x) = x.code()
                && x.contains("1555")
            {
                // the hash is already in the DB, just send the link
                return HttpResponse::Ok().json(JsonResponse {
                    url: format!("{}/{}", domain.as_str(), link_hash),
                });
            } else {
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "The server was unable to process the file.".into(),
                });
            }
        }
    };

    if filedata.data.len() > ByteSize::mib(20).as_u64() as usize
        && filedata.data.len() < ByteSize::gib(1).as_u64() as usize
    {
        // DO NOT AWAIT THIS, ITS SUPPOSED TO RUN AS A BACKGROUND TASK WHILE WE
        // GIVE INSTANT RESPONSE TO USER
        #[allow(clippy::let_underscore_future)]
        let _ = spawn(async move {
            let encoded_blob = match util::encode_media(
                match filedata.filetype.type_().as_str() {
                    "image" => util::MediaType::Image,
                    "video" => util::MediaType::Video,
                    _ => {
                        eprintln!("media mime type incompatible");
                        return;
                    }
                },
                hash.clone(),
                &filedata.data.clone(),
            )
            .await
            {
                Ok(encoded_blob) => encoded_blob,
                Err(e) => {
                    error!("an error occurred encoding media: {:?}", e);
                    return;
                }
            };

            match sqlx::query!(
                "UPDATE media SET embeddable_file = ? WHERE hash = ?",
                encoded_blob,
                hash
            )
            .execute(&**sql)
            .await
            {
                Ok(_) => {}
                Err(_) => {
                    eprintln!("unable to upload media to db");
                }
            };
        });
    }

    HttpResponse::Ok().json(JsonResponse {
        url: format!("{}/{}", domain.as_str(), link_hash),
    })
}

#[post("/remove/{hash}")]
async fn remove_media(
    sql: web::Data<Pool<Sqlite>>,
    hash: web::Path<String>,
    session: Session,
) -> impl Responder {
    match sqlx::query!(
        "DELETE FROM media WHERE hash = ? AND owner = ?",
        *hash,
        session.user.id
    )
    .execute(&**sql)
    .await
    {
        Ok(_) => HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .cookie(
                Cookie::build("msg", "media deleted")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish(),
        Err(_) => HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .cookie(
                Cookie::build("msg", "unable to delete media")
                    .path("/")
                    .secure(true)
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .finish(),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Query {
    url: String,
    text: Option<String>,
    key: String,
}

#[post("/shorten")]
async fn shorten(sql: web::Data<Pool<Sqlite>>, query: web::Query<Query>) -> impl Responder {
    let apikey = query.key.clone();

    let _ = if let Ok(x) = sqlx::query_as!(User, "SELECT * FROM users WHERE apikey = ?", apikey)
        .fetch_one(&**sql)
        .await
    {
        x
    } else {
        return HttpResponse::Forbidden().finish();
    };

    static XD: OnceCell<String> = OnceCell::new();

    HttpResponse::Ok()
        .content_type(ContentType::octet_stream())
        .body(
            format!(
                "{}{}{}",
                query.text.clone().unwrap_or_default(),
                XD.get_or_init(|| {
                    let mut string = String::new();
                    for _ in 0..250 {
                        string.push_str("||​||");
                    }
                    string
                }),
                query.url
            )
            .into_bytes(),
        )
}

// #[get("/list")]
// async fn list(sql: web::Data<Pool<Sqlite>>, session: Session) -> impl Responder {
//     #[derive(Debug, Serialize)]
//     struct Query {
//         pub hash: String,
//         pub mime: String,
//         pub owner: i64,
//         pub filename: String,
//         pub size: i32,
//         #[serde(with = "time::serde::iso8601")]
//         pub added: OffsetDateTime,
//     }
//     match sqlx::query_as!(
//         Query,
//         "SELECT hash, mime, owner, filename, LENGTH(file) AS \"size!: i32\", added AS \"added: OffsetDateTime\" FROM media WHERE owner = ?",
// 		session.user.id
//     )
//     .fetch_all(&**sql)
//     .await
//     {
// 		Ok(x) => {
//         	HttpResponse::Ok().json(x)
// 		},
// 		Err(x) => {
// 			debug!("{}", x);
//         	HttpResponse::InternalServerError().finish()
// 		}
//     }
// }

pub fn configure(cfg: &mut web::ServiceConfig) {
    let scope = web::scope("")
        // .guard(guard::fn_guard(|ctx| {
        //     ctx.head()
        //         .uri
        //         .path()
        //         .split('/')
        //         .last()
        //         .is_some_and(|x| x.len() == 576)
        // }))
        .service(get);

    cfg.service(upload)
        .service(remove_media)
        .service(shorten)
        .service(scope);
}
