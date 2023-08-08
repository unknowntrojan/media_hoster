use actix_web::{get, http, web, HttpRequest, HttpResponse, Responder, cookie::Cookie};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use serde::Serialize;
use sqlx::{Pool, Sqlite};
use time::{format_description, OffsetDateTime};

use crate::{auth::Session, util};

fn header() -> Markup {
    html! {
        (DOCTYPE)
        meta charset="utf-8";
        meta name="viewport" content="width=device-width, initial-scale=1.0";
        title { "chloride.cc" }
        script src="https://cdn.tailwindcss.com" {}
        script src="https://unpkg.com/feather-icons" {}
        script {
            (PreEscaped("window.onload = (event) => {
				feather.replace();
			};"))
        }
    }
}

fn messagebox(msg: &str) -> Markup {
	html! {
		div class="p-4 border-4 border-rose-500 text-rose-500 mb-4 text-center" {
			h2 {
				(msg)
			}
		}
	}
}

#[get("/")]
async fn index(
    req: HttpRequest,
    session: Option<Session>,
    sql: web::Data<Pool<Sqlite>>,
) -> impl Responder {
    let session = match session {
        Some(x) => x,
        None => {
            return HttpResponse::TemporaryRedirect()
                .append_header((http::header::LOCATION, "/login"))
                .finish();
        }
    };

    let flash = match req.cookie("msg") {
		Some(x) => {
			messagebox(x.value())
		}, None => {
			html! {}
		}
	};

    #[derive(Debug, Serialize)]
    struct Query {
        pub hash: String,
        pub mime: String,
        pub owner: i64,
        pub filename: String,
        pub size: i32,
        pub embed_size: i32,
        #[serde(with = "time::serde::iso8601")]
        pub added: OffsetDateTime,
    }

    let format =
        format_description::parse("[day].[month].[year] [hour]:[minute]:[second]").unwrap();

	fn link_from_hashstr(string: &str) -> String {
		format!(
			"/{}",
			string
		)
	}

	let user_usage = if let Ok(user_usage) = sqlx::query!("SELECT COALESCE(SUM(LENGTH(file)), SUM(LENGTH(embeddable_file))) AS len FROM media WHERE owner = ?", session.user.id).fetch_one(&**sql).await {
		if let Some(len) = user_usage.len {
			len
		} else {
			0i64
		}
	} else {
		0i64
	};

	let user_usage = (user_usage as f64) / 1024f64 / 1024f64;

	let user_usage = format!("{user_usage:.2}MB");

    let media: Markup = match sqlx::query_as!(
        Query,
        "SELECT hash, mime, owner, filename, LENGTH(file) AS \"size!: i32\", LENGTH(embeddable_file) AS \"embed_size!: i32\", added AS \"added: OffsetDateTime\" FROM media WHERE owner = ? ORDER BY added DESC",
		session.user.id
    ).fetch_all(&**sql)
    .await
    {
        Ok(x) => { 
			html! {				
				br;
				br;
				table class="table-auto w-96 overflow-y-auto" {
					tr class="text-center odd:bg-zinc-800 even:bg-zinc-900 hover:bg-cyan-700" {
						th class="whitespace-nowrap px-4" { "Preview" }
						th class="whitespace-nowrap px-4" { "Hash" }
						th class="whitespace-nowrap px-4" { "Filename" }
						th class="whitespace-nowrap px-4" { "MIME" }
						th class="whitespace-nowrap px-4" { "Size" }
						th class="whitespace-nowrap px-4" { "Added on" }
						th class="whitespace-nowrap px-4" { "Actions" }
					}
					@for entry in x {
						tr class="text-center odd:bg-zinc-800 even:bg-zinc-900 hover:bg-cyan-700" {
							td class="whitespace-nowrap px-4" { a href=({ link_from_hashstr(&entry.hash) }) { img class="rounded-md max-h-[90px] max-w-[160px] min-h-[90px] min-w-[160px] object-contains display:block" src=({ link_from_hashstr(&entry.hash) }); } }
							td class="whitespace-nowrap px-4" { a href=({ link_from_hashstr(&entry.hash) }) { (entry.hash) } }
							td class="whitespace-nowrap px-4" { (entry.filename) }
							td class="whitespace-nowrap px-4" { (entry.mime) }
							td class="whitespace-nowrap px-4" { (entry.size) " bytes" br; (if entry.embed_size != 0 { format!(" ({} bytes encoded)", entry.embed_size) } else { "".into() }) }
							td class="whitespace-nowrap px-4" { (entry.added.format(&format).unwrap()) }
							td class="whitespace-nowrap px-4" {
								div class="flex flex-row" {
									button type="button" onclick=(format!("navigator.clipboard.writeText(window.location + '{}')", link_from_hashstr(&entry.hash))) class="mx-1 rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-1 display:inline justify:center" {
										i class="m-auto" data-feather="link" {}
									}
									form action=({ format!("/remove/{}", &entry.hash) }) method="post" class="m-auto" {
										button type="submit" class="mx-1 rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-1 display:inline justify:center" {
											i class="m-auto" data-feather="trash-2" {}
										}
									}
								}
							}
						}
					}
				}
			}
		},
		Err(_) => {
        	messagebox("error fetching media")
		}
    };

    let body = html! {
        (header())
        body class="select-none bg-zinc-800 text-[#f2f7f2]" {
			div class="flex flex-row w-full" {
				// navbar
				div class="p-4" {
                    "Hi, " (session.user.username) "!"
					br;
					"You are using " (user_usage) " of space."
					br;
				}

				div class="flex flex-row justify-center w-1/3 mr-auto my-auto" {
					form action="/users/invite" method="post" class="m-auto" {
						button type="submit" class="rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-2 display:inline justify:center" {
							"Generate Invite"
						}
					}
					form action="/users/uploader" method="get" class="m-auto" {
						button type="submit" class="rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-2 display:inline justify:center" {
							"ShareX Uploader"
						}
					}
					form action="/users/shortener" method="get" class="m-auto" {
						button type="submit" class="rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-2 display:inline justify:center" {
							"ShareX Shortener"
						}
					}
					form action="/users/invalidate_apikey" method="post" class="m-auto" {
						button type="submit" class="rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-2 display:inline justify:center" {
							"Invalidate API key"
						}
					}
				}
				
			}
            div class="flex flex-col w-full h-full" {
                div class="m-auto text-center" {
					(flash)
                    br;
                    (media)
                }
            }
        }
    };

    let mut builder = HttpResponse::Ok().body(body.into_string());
	builder.add_removal_cookie(&Cookie::named("msg")).unwrap();
	builder
}

#[get("/login")]
async fn login(req: HttpRequest, session: Option<Session>) -> impl Responder {
    if session.is_some() {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .finish();
    }

	let flash = match req.cookie("msg") {
		Some(x) => {
			messagebox(x.value())
		}, None => {
			html! {}
		}
	};

    let body = html! {
        (header())
        body class="select-none bg-zinc-800 text-[#f2f7f2]" {
            div class="flex flex-col w-screen h-screen" {
                div class="m-auto" {
					(flash)
                    h1 class="justify-center text-center" {
                        "login"
                    }
                    form action="/users/login" method="post" class="mt-4 flex flex-col" {
                        input type="text" name="username" placeholder="username" autocomplete="off" class="rounded-lg mb-4 bg-zinc-700 py-1 px-2 focus:outline-cyan-700 drop-shadow-2xl placeholder:italic text-center caret-transparent";
                        input type="password" name="password" placeholder="password" autocomplete="off" class="rounded-lg mb-4 bg-zinc-700 py-1 px-2 focus:outline-cyan-700 placeholder:italic text-center caret-transparent";
                        button type="submit" class="rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-1 display:inline justify:center" {
                            i class="m-auto" data-feather="log-in" {}
                        }
						br;
						br;
						a href="/register" class="justify-center text-center mt-8" {
							"register instead"
						}
                    }					
                }
            }
        }
    };

    let mut builder = HttpResponse::Ok().body(body.into_string());
	builder.add_removal_cookie(&Cookie::named("msg")).unwrap();
	builder
}

#[get("/register")]
async fn register(req: HttpRequest, session: Option<Session>) -> impl Responder {
    if session.is_some() {
        return HttpResponse::Found()
            .append_header((http::header::LOCATION, "/"))
            .finish();
    }

	let flash = match req.cookie("msg") {
		Some(x) => {
			messagebox(x.value())
		}, None => {
			html! {}
		}
	};

    let body = html! {
        (header())
        body class="select-none bg-zinc-800 text-[#f2f7f2]" {
            div class="flex flex-col w-screen h-screen" {
                div class="m-auto" {
					(flash)
                    h1 class="justify-center text-center" {
                        "register"
                    }
                    form action="/users/register" method="post" class="mt-4 flex flex-col" {
                        input type="text" name="username" placeholder="username" autocomplete="off" class="rounded-lg mb-4 bg-zinc-700 py-1 px-2 focus:outline-cyan-700 drop-shadow-2xl placeholder:italic text-center caret-transparent";
                        input type="password" name="password" placeholder="password" autocomplete="off" class="rounded-lg mb-4 bg-zinc-700 py-1 px-2 focus:outline-cyan-700 drop-shadow-2xl placeholder:italic text-center caret-transparent";
                        input type="text" name="invite" placeholder="invite" autocomplete="off" class="rounded-lg mb-4 bg-zinc-700 py-1 px-2 focus:outline-cyan-700 drop-shadow-2xl placeholder:italic text-center caret-transparent";
                        button type="submit" class="rounded-lg m-auto block text-center bg-zinc-700 hover:bg-cyan-700 py-1 px-1 display:inline justify:center" {
                            i class="m-auto" data-feather="user-plus";
                        }
                    }
                }
            }
        }
    };

    let mut builder = HttpResponse::Ok().body(body.into_string());
	builder.add_removal_cookie(&Cookie::named("msg")).unwrap();
	builder
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(index).service(login).service(register);
}
