use sqlx::FromRow;
use time::OffsetDateTime;

#[derive(Debug, FromRow)]
pub struct User {
    pub id: i64,
    pub apikey: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, FromRow)]
pub struct Media {
    pub hash: String,
    pub mime: String,
    pub owner: i64,
    pub added: OffsetDateTime,
    pub filename: String,
    pub file: Vec<u8>,
    pub embeddable_file: Option<Vec<u8>>,
}

#[derive(Debug, FromRow)]
pub struct Session {
    pub id: i64,
    pub user: i64,
    pub token: String,
    pub created: OffsetDateTime,
}

#[derive(Debug, FromRow)]
pub struct Invite {
    pub id: i64,
    pub token: String,
    pub invited: Option<i64>,
}
