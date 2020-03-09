use std::cell::RefCell;
use std::collections::HashMap;
use std::{fmt, iter};

use lazy_static::lazy_static;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use reqwest;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

const STATE_LENGTH: usize = 16;

#[derive(Hash, Eq, PartialEq)]
pub enum Provider {
    Google,
    Facebook,
    // GitHub,
    // Twitter,
    // Instagram,
}

pub struct OAuth {
    provider: Provider,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    state: String,
    access_token: RefCell<String>,
}

#[derive(Deserialize, Debug)]
pub struct UserProfile {
    id: String,
    name: String,
    first_name: String,
    last_name: String,
    email: String,
}

// TODO: https://docs.rs/enum-display-derive/0.1.0/enum_display_derive/ ?
impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Provider::Google => f.write_str("Google"),
            Provider::Facebook => f.write_str("Facebook"),
            // Provider::GitHub => f.write_str("GitHub"),
        }
    }
}

lazy_static! {
    static ref BASE_AUTHORIZATION_URL: HashMap<Provider, &'static str> = {
        let mut map = HashMap::new();
        map.insert(
            Provider::Google,
            "https://accounts.google.com/o/oauth2/auth",
        );
        map.insert(
            Provider::Facebook,
            "https://www.facebook.com/v2.8/dialog/oauth",
        );
        // map.insert(Provider::GitHub, "https://github.com/login/oauth/authorize");
        map
    };
}

lazy_static! {
    static ref TOKEN_URL: HashMap<Provider, &'static str> = {
        let mut map = HashMap::new();
        map.insert(
            Provider::Google,
            "https://www.googleapis.com/oauth2/v4/token",
        );
        map.insert(
            Provider::Facebook,
            "https://graph.facebook.com/v2.8/oauth/access_token",
        );
        // map.insert(
        //     Provider::GitHub,
        //     "https://github.com/login/oauth/access_token",
        // );
        map
    };
}

lazy_static! {
    static ref PROFILE_URL: HashMap<Provider, &'static str> = {
        let mut map = HashMap::new();
        map.insert(
            Provider::Google,
            "https://www.googleapis.com/plus/v1/people/me",
        );
        map.insert(
            Provider::Facebook,
            "https://graph.facebook.com/v2.8/me",
        );
        // map.insert(
        //     Provider::GitHub,
        //     "https://api.github.com/user",
        // );
        map
    };
}

lazy_static! {
    static ref DEFAULT_SCOPE: HashMap<Provider, Vec<&'static str>> = {
        let mut map = HashMap::new();
        map.insert(
            Provider::Google,
            vec![
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email",
            ],
        );
        map.insert(Provider::Facebook, vec!["email"]);
        // map.insert(Provider::GitHub, vec!["read:user", "user:email"]);
        map
    };
}

impl OAuth {
    pub fn new(
        provider: Provider,
        client_id: &String,
        client_secret: &String,
        redirect_uri: &String,
    ) -> OAuth {
        OAuth {
            provider: provider,
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            redirect_uri: redirect_uri.clone(),
            state: iter::repeat(())
                .map(|()| thread_rng().sample(Alphanumeric))
                .take(STATE_LENGTH)
                .collect::<String>(),
            access_token: RefCell::new(String::new()),
        }
    }

    /// Returns the authorization URL for the requested scope
    pub fn authorization_url(&self, scope: Vec<&str>) -> Result<String, String> {
        let base_url = BASE_AUTHORIZATION_URL.get(&self.provider).ok_or(format!(
            "unable to get authorization URL: unknown provider '{}'",
            &self.provider
        ))?;
        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert("client_id", &self.client_id);
        params.insert("redirect_uri", &self.redirect_uri);
        params.insert("response_type", "code");
        params.insert("state", &self.state);
        // scope should be a a space-delimited list
        let scope_qs = scope.join(" ");
        params.insert("scope", &scope_qs);
        let url = Url::parse_with_params(&base_url, &params).map_err(|e| e.to_string())?;

        Ok(url.to_string())
    }

    /// Very high-level function
    pub fn user_profile(&self) -> Result<UserProfile, String> {
        // we can only proceed if the access token has been fetched
        if self.access_token.borrow().trim().is_empty() {
            return Err("access token not set; help: call `fetch_token`".to_string());
        }

        match self.provider {
            Provider::Facebook => self.user_profile_facebook(),
            Provider::Google => Err("not yet".to_string()),
        }

        // Google
        // headers = {'Authorization': 'Bearer ' + data['access_token']}
        // url = 'https://www.googleapis.com/plus/v1/people/me'
        // async with client.get(url, headers=headers) as resp:
        //     profile = await resp.json()
        // log.debug('g+ profile: %s', pformat(profile))
        // email = None
        // for e in profile.get('emails', []):
        //     if e['type'] == 'account':
        //         email = e['value']
        //         break
        // name = profile['displayName'] or profile.get('name', {}).get('givenName')
    }

    pub fn fetch_token(&self, redirect_response: &String) -> Result<(), String> {
        let base_url = TOKEN_URL.get(&self.provider).ok_or(format!(
            "unable to fetch access token: unknown provider '{}'",
            &self.provider
        ))?;
        // confirm that the `state` returned matches the value sent
        if !self.check_state(redirect_response) {
            return Err(format!(
                "possible XSS attack: expected state={}",
                self.state
            ));
        }
        // fetch the code from the URL
        let code = get_query_string_param(redirect_response, &"code".to_string())
            .ok_or("could not find the code in the response URL".to_string())?;
        // prepare the query string parameters
        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert("client_id", &self.client_id);
        params.insert("redirect_uri", &self.redirect_uri);
        params.insert("client_secret", &self.client_secret);
        params.insert("code", &code);
        // POST the request for the access token
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(&base_url.to_string())
            .form(&params)
            .send()
            .map_err(|e| e.to_string())?;
        // retrieve the body (json) and parse it into a map-like data structure
        let body: Value = res.json().map_err(|e| e.to_string())?;
        // fetch the access token
        let access_token = body
            .get("access_token")
            .ok_or("could not find 'access_token' in the response".to_string())
            .map(|t| t.to_string())?;
        // save the access token
        // when using `Value` any fields of the `String` type will be surrounded by ""
        // https://github.com/serde-rs/json/issues/367
        *self.access_token.borrow_mut() = access_token.trim_matches('"').to_string();

        Ok(())
    }

    /// Returs `true` iff the `state` parameter in `url`'s query string matches the one originally provided
    fn check_state(&self, url: &String) -> bool {
        match get_query_string_param(url, &"state".to_string()) {
            Some(v) => v == self.state,
            None => false,
        }
    }

    fn user_profile_facebook(&self) -> Result<UserProfile, String> {
        let base_url = PROFILE_URL.get(&self.provider).ok_or(format!(
            "unable to fetch profile: unknown provider '{}'",
            &self.provider
        ))?;
        let access_token = self.access_token.borrow();
        // query string parameters
        let mut params: HashMap<&str, &str> = HashMap::new();
        params.insert("access_token", &access_token);
        params.insert("fields", "id,email,name,first_name,last_name");
        // build the full URL
        let url = Url::parse_with_params(&base_url, &params).map_err(|e| e.to_string())?;
        // fetch the user profile
        let profile: UserProfile = reqwest::blocking::get(url.clone())
            .map_err(|e| e.to_string())?
            .json()
            .map_err(|e| e.to_string())?;

        Ok(profile)
    }
}

fn get_query_string_param(url: &String, param: &String) -> Option<String> {
    match Url::parse(&url) {
        Ok(u) => {
            for (k, v) in u.query_pairs().into_owned() {
                if k == *param {
                    return Some(v);
                }
            }
        }
        Err(_) => return None,
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_url() -> Result<(), String> {
        let oa = OAuth::new(
            Provider::Facebook,
            &"id".to_string(),
            &"secret".to_string(),
            &"redirect".to_string(),
        );
        let au = oa.authorization_url(vec!["email"])?;
        // parse the returned URL to de-construct it and confirm the parameters
        let u = Url::parse(&au).unwrap();
        assert_eq!(u.host_str(), Some("www.facebook.com"));
        for (k, v) in u.query_pairs().into_owned() {
            match k.as_str() {
                "client_id" => assert_eq!(v, "id"),
                "redirect_url" => assert_eq!(v, "redirect"),
                "scope" => assert_eq!(v, "email"),
                _ => (),
            }
        }

        Ok(())
    }

    #[test]
    fn test_check_state() -> Result<(), String> {
        let oa = OAuth::new(
            Provider::Facebook,
            &"3143960285829409".to_string(),
            &"shhhh".to_string(),
            &"localhost".to_string(),
        );
        let au = oa.authorization_url(vec!["email"])?;

        // make sure the correct query string parameter is found
        assert!(oa.check_state(&au));
        // make sure the check returns false if the state is not found
        assert_eq!(
            oa.check_state(&"https://localhost:8080/?code=THE_CODE&state=NOPE#_=_".to_string()),
            false
        );

        Ok(())
    }

    #[test]
    fn test_user_profile() {
        let oa = OAuth::new(
            Provider::Facebook,
            &"3143960285829409".to_string(),
            &"shhhh".to_string(),
            &"localhost".to_string(),
        );
        assert!(oa.user_profile().is_err());
        *oa.access_token.borrow_mut() = "fake_access_token".to_string();
        assert!(oa.user_profile().is_ok());
    }

    #[test]
    fn test_get_query_string_param() {
        // invalid URL
        assert_eq!(
            get_query_string_param(&"nope".to_string(), &"param".to_string()),
            None
        );
        // no query string
        assert_eq!(
            get_query_string_param(&"http://localhost".to_string(), &"param".to_string()),
            None
        );
        // query string without the parameter requested
        assert_eq!(
            get_query_string_param(&"http://localhost?a=b".to_string(), &"param".to_string()),
            None
        );
        // valid query string
        assert_eq!(
            get_query_string_param(
                &"http://localhost?a=b&param=foo".to_string(),
                &"param".to_string()
            ),
            Some("foo".to_string())
        );
    }
}
