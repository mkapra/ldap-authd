use anyhow::Result;
use clap::Parser;
use tide::{Request, StatusCode};

use ldap_authd::{
    get_ldap_options_from_headers, get_userdata_from_authorization, query_ldap,
    unauthorized_response, validate_auth_header, Cli,
};

async fn auth_get(req: Request<()>) -> tide::Result {
    let auth_header = req.header("Authorization").map(|h| h.as_str());
    if validate_auth_header(auth_header).is_err() {
        return Ok(unauthorized_response());
    }
    let auth_header = auth_header.unwrap();

    let (username, password) = &get_userdata_from_authorization(auth_header)?;
    let ldap_options = get_ldap_options_from_headers(&req);
    if ldap_options.is_err() {
        // Should not happen if the configuration of the nginx server is correct
        return Ok(StatusCode::BadRequest.into());
    }
    let ldap_options = ldap_options.unwrap();

    if query_ldap((username, password), ldap_options).is_err() {
        // User is not in queried group
        return Ok(unauthorized_response());
    }

    Ok(StatusCode::Ok.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tide::log::with_level(tide::log::LevelFilter::Debug);

    let mut app = tide::new();
    app.with(tide::log::LogMiddleware::new());
    app.at(&args.auth_endpoint).get(auth_get);
    app.listen(format!("{}:{}", args.hostname, args.port))
        .await?;
    Ok(())
}
