use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::collections::{hash_map, HashMap};

#[derive(Clone)]
pub struct OidConf<'a> {
    pub jwks: HashMap<String, DecodingKey<'a>, hash_map::RandomState>,
    pub issuer: String,
}

pub async fn get_config<'a>(uri: &str) -> anyhow::Result<OidConf<'a>> {
    let oidc =
        get_json::<Oid>(&(uri.to_string() + "/v2.0/.well-known/openid-configuration")).await?;
    let jwks = get_json::<JWKS>(&oidc.jwks_uri)
        .await?
        .keys
        .iter()
        .filter(|jwk| jwk.kty == Some("RSA".into()))
        .filter_map(|jwk| Some((jwk.kid.as_ref()?, jwk.n.as_ref()?, jwk.e.as_ref()?)))
        .fold(HashMap::new(), |mut dec_keys, v| {
            dec_keys.insert(
                v.0.into(),
                DecodingKey::from_rsa_components(&v.1, &v.2).into_static(),
            );
            dec_keys
        });
    Ok(OidConf {
        jwks,
        issuer: oidc.issuer,
    })
}

async fn get_json<'a, T>(uri: &str) -> anyhow::Result<T>
where
    for<'de> T: Deserialize<'de> + 'a,
{
    Ok(reqwest::get(uri).await?.json::<T>().await?)
}

#[derive(Deserialize)]
struct Oid {
    jwks_uri: String,
    issuer: String,
}

#[derive(Clone, Debug, Deserialize)]
struct JWK {
    kty: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct JWKS {
    keys: Vec<JWK>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_jwks() {
        let disc = "/v2.0/.well-known/openid-configuration";
        let some_uri = reqwest::Url::parse(&mockito::server_url())
            .unwrap()
            .join("/common/discovery/keys")
            .unwrap();
        let disc_body = format!(r#"{{"jwks_uri": "{}", "issuer": ""}}"#, some_uri);
        let jwk_body = r#" { "keys": [ {
                        "kty": "RSA",
                        "e": "AQAB",
                        "n": "actually a big int base 64 encoded as a string",
                        "kid": "N" },
                        {"kty":"oct",
                         "use":"sig",
                         "kid":"hmac",
                         "k":"SECRET_2gtzk"}] } "#;

        serde_json::from_str::<JWKS>(&jwk_body).unwrap();

        let disc_mock = mockito::mock("GET", disc)
            .with_header("content-type", "application/json")
            .with_body(disc_body)
            .expect(1)
            .create();

        let jwk_mock = mockito::mock("GET", some_uri.path())
            .with_header("content-type", "application/json")
            .with_body(jwk_body)
            .expect(1)
            .create();
        let conf = get_config(&mockito::server_url()).await.unwrap();
        assert_eq!(conf.jwks.len(), 1);
        assert_ne!(conf.jwks.get("N"), None);

        jwk_mock.assert();
        disc_mock.assert();
    }
}
