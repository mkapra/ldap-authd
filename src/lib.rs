use std::{collections::HashMap, str};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine};
use clap::Parser;
use lazy_static::lazy_static;
use ldap3::{LdapConn, Scope};
use ldap3::SearchEntry;
use log::{debug, info};
use regex::Regex;
use tide::{Request, Response, StatusCode};

/// (username, password)
type UserInfo<'a> = (&'a str, &'a str);

lazy_static! {
    static ref BASIC_HTTP_RE: Regex = Regex::new(r"[bB]asic (.*)").unwrap();
}
const LDAP_HEADERS: &[&str] = &[
    "X-Ldap-URL",
    "X-Ldap-BaseDN",
    "X-Ldap-BindDN",
    "X-Ldap-BindPass",
    "X-Ldap-Template",
];

#[derive(Parser, Debug)]
pub struct Cli {
    /// Host to bind
    #[arg(long, default_value = "localhost")]
    pub hostname: String,
    /// Port to bind
    #[arg(short, long, default_value = "8888")]
    pub port: i32,
    /// The endpoint the authentication service should respond on
    #[arg(long, default_value = "/auth-proxy")]
    pub auth_endpoint: String,
}

/// Returns a unauthorized Response
///
/// This response includes a header which suggests the browser which authentication methods can be
/// used.
pub fn unauthorized_response() -> Response {
    Response::builder(StatusCode::Unauthorized)
        // Header necessary for authentication popup
        .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
        .build()
}

/// Validates if the given `Authorization` header has the desired format
pub fn validate_auth_header(header: Option<&str>) -> Result<()> {
    debug!("Validating authorization header");
    if header.is_none() {
        bail!("Authorization header is missing");
    }
    if !header.unwrap().to_lowercase().contains("basic") {
        bail!("Authorization header has invalid format");
    }
    Ok(())
}

/// Tries extracting the username from the given `Authorization` header
pub fn get_userdata_from_authorization(header: &str) -> Result<(String, String)> {
    debug!("Extracting base64 string from authorization header");
    let authorization = BASIC_HTTP_RE.captures(header);
    let authorization = authorization.unwrap().get(1).unwrap().as_str();
    debug!("Decoding authentication string");
    let decoded = general_purpose::STANDARD
        .decode(authorization)
        .context("Could not decode base64")?;
    debug!("Extracting username from decoded authentication string");
    let mut splitted_auth = str::from_utf8(&decoded)
        .context("Could not decode base64")?
        .split(':')
        .collect::<Vec<&str>>();

    let username = splitted_auth.remove(0).trim().to_string();
    let password = splitted_auth.remove(0).trim().to_string();

    Ok((username, password))
}

/// Returns the necessary options for querying the LDAP server from the request headers
pub fn get_ldap_options_from_headers(req: &Request<()>) -> Result<HashMap<String, &str>> {
    debug!("Extracting ldap options from request headers");
    let mut header_map: HashMap<String, &str> = HashMap::new();
    for header in LDAP_HEADERS {
        match req.header(*header) {
            Some(x) => header_map.insert(header.to_string(), x.last().as_str()),
            // A header is missing. This should not be the case and is a bad request because of
            // that
            None => bail!("{} header is missing", header),
        };
    }
    Ok(header_map)
}

/// Queries the LDAP server for the given username and checks for a correct password
///
/// # Returns
///
/// This function returns [`Ok`] if the filter was successful. When the filter did not find any
/// result or the ldap server responded with an error (e.g. invalid password), an [`Err`] is returned
pub fn query_ldap(
    (username, password): UserInfo,
    ldap_options: HashMap<String, &str>,
) -> Result<()> {
    debug!("Starting ldap connection");
    let mut ldap = LdapConn::new(ldap_options.get("X-Ldap-URL").unwrap())?;

    // Prepare searchfilter
    let filter = ldap_options
        .get("X-Ldap-Template")
        .unwrap()
        .replace("%(username)s", username);

    debug!("Querying with filter {:?}", &filter);
    let (rs, _res) = ldap
        .search(
            ldap_options.get("X-Ldap-BaseDN").unwrap(),
            Scope::Subtree,
            &filter,
            Vec::<&str>::new(),
        )?
        .success()?;

    debug!("Closing ldap connection");
    ldap.unbind()?;

    if rs.is_empty() {
        bail!("User not found with given filter");
    }

    let user_dn = SearchEntry::construct(rs.first().unwrap().clone()).dn;
    debug!("Checking if the password of user '{}' is correct", username);
    let mut ldap = LdapConn::new(ldap_options.get("X-Ldap-URL").unwrap())?;
    let ldap_bind = ldap.simple_bind(&user_dn, password);

    if ldap_bind.is_err() {
        ldap.unbind()?;
        debug!("Password for user is invalid");
        bail!("Password invalid");
    }
    if ldap_bind?.success().is_err() {
        debug!("Password for user is invalid");
        bail!("Password invalid");
    }

    ldap.unbind()?;

    info!("Auth data for user {} correctly", username);

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_authdata() {
        let test_authheader = "Basic bWthcHJhOnRlc3QxMjMK";
        assert_eq!(
            get_userdata_from_authorization(test_authheader).unwrap(),
            ("mkapra".to_string(), "test123".to_string())
        );
    }

    #[test]
    fn test_validate_authheader() {
        let valid_authheader = "Basic bWthcHJhOnRlc3QxMjMK";
        let missing_basic = "bWthcHJhOnRlc3QxMjMK";
        let missing_header = None;

        assert!(validate_auth_header(Some(valid_authheader)).is_ok());
        assert!(validate_auth_header(Some(missing_basic)).is_err());
        assert!(validate_auth_header(missing_header).is_err());
    }
}
