use std::{error::Error, pin::Pin};

use actix_web::{web, FromRequest};
use argon2::{
	password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
	Argon2, PasswordHash,
};
use futures_util::Future;
use sqlx::{Pool, Sqlite};

use crate::model::User;

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
	let argon2 = Argon2::default();
	let salt = SaltString::generate(&mut OsRng);

	let hash = argon2
		.hash_password(password.as_bytes(), &salt)?
		.to_string();

	let parsed_hash = PasswordHash::new(&hash)?;

	// Verify hash immediately after creation
	let verify_result = argon2.verify_password(password.as_bytes(), &parsed_hash);

	match verify_result {
		Ok(_) => Ok(hash),
		Err(e) => Err(e),
	}
}

pub fn verify_password(password: &str, hash: &str) -> Result<(), argon2::password_hash::Error> {
	Argon2::default().verify_password(password.as_bytes(), &PasswordHash::new(hash)?)
}

pub struct Session {
	pub user: User,
}

impl FromRequest for Session {
	type Error = Box<dyn Error>;
	type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

	fn from_request(
		req: &actix_web::HttpRequest,
		_payload: &mut actix_web::dev::Payload,
	) -> Self::Future {
		let req = req.clone();
		Box::pin(async move {
			let sql = if let Some(x) = req.app_data::<web::Data<Pool<Sqlite>>>() {
				x
			} else {
				return Err("unable to retrieve db".into());
			};

			let token = if let Some(x) = req.cookie("token") {
				x
			} else {
				return Err("no token present".into());
			};

			let token = token.value();

			// 7 days in seconds
			const EXPIRY: u32 = 60 * 60 * 24 * 7;

			let user = sqlx::query_as!(
				User,
				"SELECT a.* FROM users a, sessions b WHERE b.token = ? AND (b.created + ?) > UNIXEPOCH() AND a.id = b.user",
				token,
				EXPIRY
			)
			.fetch_one(&***sql)
			.await?;

			Ok(Session { user })
		})
	}
}
