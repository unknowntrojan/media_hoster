use actix_web::{
    cookie::{Cookie, SameSite},
    get, http, post, web, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

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

    if let Ok(_) = auth::verify_password(form.password.as_str(), user.password.as_str()) && let Ok(_) = sqlx::query!("INSERT INTO sessions (user, token) VALUES(?, ?)", user.id, token).execute(&**sql).await {
		HttpResponse::Found().cookie(Cookie::build("token", token).path("/").secure(true).http_only(true).same_site(SameSite::Strict).finish()).append_header((http::header::LOCATION, "/")).finish()
	} else {
		// Unauthorized
		HttpResponse::Found()
		.append_header((http::header::LOCATION, "/login")).cookie(
			Cookie::build("msg", "login failed")
				.path("/")
				.secure(true)
				.http_only(true)
				.same_site(SameSite::Strict)
				.finish(),
		).finish()
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

#[get("/sxcu")]
async fn sharex(domain: web::Data<String>, session: Session) -> impl Responder {
    // generate a SXCU file.

    #[derive(Serialize)]
    struct Sxcu {
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

    let sxcu = Sxcu {
        version: "14.0.0".into(),
        name: "u.w".into(),
        file_form_name: "unknown".into(),
        destination_type: "ImageUploader, FileUploader".into(),
        request_method: "POST".into(),
        request_url: format!("{}/upload?key={}", domain.as_str(), session.user.apikey),
        body: "MultipartFormData".into(),
        url: "{json:url}".into(),
        error_msg: "{json:error}".into(),
    };

    HttpResponse::Ok()
        .append_header(("Content-Disposition", "attachment; filename=uw.sxcu"))
        .json(sxcu)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    let scope = web::scope("/users")
        // .service(list)
        .service(sharex)
        .service(login)
        .service(register)
        .service(invalidate_apikey);

    cfg.service(scope);
}
