use std::{env, io};

use simple_oauth_login::{OAuth, Provider};

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        return Err(format!(
            "usage: {} <provider> <client_id> <redirect_url> <secret>",
            &args[0]
        ));
    }

    let provider: Provider = match args[1].as_str() {
        "facebook" => Provider::Facebook,
        "google" => Provider::Google,
        _ => panic!("unknown provider"),
    };
    let client_id: &String = &args[2];
    let redirect_url: &String = &args[3];
    let client_secret: &String = &args[4];

    // needs to be mut as
    let oauth = OAuth::new(provider, client_id, client_secret, redirect_url);

    // redirect the user to `auth_url` to start the authentication flow
    let auth_url = oauth.authorization_url()?;
    println!("open in a browser: {}", auth_url);

    // get the full URL to which the user is redirected
    println!("enter the URL you were redirected to: ");
    let mut redirect_url = String::new();
    io::stdin()
        .read_line(&mut redirect_url)
        .map_err(|e| e.to_string())?;

    // get the access token which will be used for all requests following up
    oauth.fetch_token(&redirect_url)?;

    // get the user profile
    let profile = oauth.user_profile()?;
    println!("user profile:\n{:?}", profile);

    Ok(())
}
