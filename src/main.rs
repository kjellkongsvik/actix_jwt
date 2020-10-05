#[macro_use]
extern crate lazy_static;
use crate::config::CONFIG;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use actix_web::{HttpResponse, Responder};
use actix_web_httpauth::middleware::HttpAuthentication;
use jsonwebtoken::{Algorithm, Validation};

mod auth;
mod config;
mod openid;

async fn index() -> impl Responder {
    HttpResponse::Ok().body("hello world")
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    env_logger::init_from_env(env_logger::Env::default().filter_or("LOG_LEVEL", ""));

    let mut aud = std::collections::HashSet::new();
    aud.insert(CONFIG.audience.clone());

    let oidc = openid::get_config(CONFIG.authserver.as_ref()).await?;

    let mut validation = Validation::default();
    validation.algorithms = vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];
    validation.iss = Some(oidc.issuer.clone());
    validation.aud = Some(aud);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(HttpAuthentication::bearer(auth::validator(
                validation.clone(),
                oidc.jwks.clone(),
            )))
            .service(web::scope("/").route("", web::get().to(index)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;

    Ok(())
}
