extern crate thrussh;
extern crate thrussh_keys;
extern crate futures;
extern crate tokio_core;
extern crate env_logger;
extern crate ring;
use std::net::SocketAddr;
use std::sync::Arc;
use thrussh::*;
use thrussh::server::{Auth, Session};
use thrussh_keys::*;

#[derive(Clone)]
struct H{}

impl server::Server for H {
    type Handler = Self;
    fn new(&self, _: SocketAddr) -> Self {
        H{}
    }
}

impl server::Handler for H {
    type Error = ();
    type FutureAuth = futures::Finished<(Self, server::Auth), Self::Error>;
    type FutureUnit = futures::Finished<(Self, server::Session), Self::Error>;
    type FutureBool = futures::Finished<(Self, server::Session, bool), Self::Error>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        futures::finished((self, auth))
    }
    fn finished_bool(self, session: Session, b: bool) -> Self::FutureBool {
        futures::finished((self, session, b))
    }
    fn finished(self, session: Session) -> Self::FutureUnit {
        futures::finished((self, session))
    }

    fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        futures::finished((self, server::Auth::Accept))
    }
    fn data(self, channel: ChannelId, data: &[u8], mut session: server::Session) -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
        session.data(channel, None, data);
        futures::finished((self, session))
    }
}

use futures::Future;

struct Client { }

impl client::Handler for Client {
    type Error = ();
    type FutureBool = futures::Finished<(Self, bool), Self::Error>;
    type FutureUnit = futures::Finished<Self, Self::Error>;
    type FutureSign = futures::Finished<(Self, CryptoVec), Self::Error>;
    type SessionUnit = futures::Finished<(Self, client::Session), Self::Error>;
    fn check_server_key(self, server_public_key: &key::PublicKey) -> Self::FutureBool {
        println!("check_server_key: {:?}", server_public_key);
        futures::finished((self, true))
    }
    fn channel_open_confirmation(self, channel: ChannelId, session: client::Session) -> Self::SessionUnit {
        println!("channel_open_confirmation: {:?}", channel);
        futures::finished((self, session))
    }
    fn data(self, channel: ChannelId, ext: Option<u32>, data: &[u8], session: client::Session) -> Self::SessionUnit {
        println!("data on channel {:?} {:?}: {:?}", ext, channel, std::str::from_utf8(data));
        futures::finished((self, session))
    }
}

impl Client {

    fn run(self, config: Arc<client::Config>, _: &str) {
        client::connect(
            "127.0.0.1:2225", config, None, self,

            |connection| {
                println!("connecting...");
                let key_location = "/Users/shella/.ssh/id_rsa";
                let key = thrussh_keys::load_secret_key(key_location, None).unwrap();
                let user = "shella";

                connection.authenticate_key(user, key)
                    .and_then(|session| {
                        session.channel_open_session().and_then(|(session, channelid)| {
                            session.data(channelid, None, "Hello, world!").and_then(|(mut session, _)| {
                                session.disconnect(Disconnect::ByApplication, "Ciao", "");
                                session
                        })
                    })
                })
        }).unwrap();
    }

}

fn main() {
    env_logger::init();

    let t = std::thread::spawn(|| {
        let mut config = thrussh::server::Config::default();
        config.connection_timeout = Some(std::time::Duration::from_secs(600));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config.keys.push(thrussh_keys::key::KeyPair::generate(thrussh_keys::key::ED25519).unwrap());
        let config = Arc::new(config);
        let sh = H{};
        println!("server running!");
        thrussh::server::run(config, "127.0.0.1:2225", sh);
    });

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);
    let sh = Client {};
    let device_config = read_toml();
    println!("{:#?}", device_config);
    sh.run(config, "127.0.0.1:2225");

    std::mem::forget(t)
}

extern crate toml;
#[macro_use]
extern crate serde_derive;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize)]
struct DeviceConfig {
    hostname: Option<String>,
    ip: Option<String>,
    port: Option<u64>,
    os: Option<String>,
    user: Option<String>,
    ssh_secretkey_path: Option<String>,
}

fn read_toml() -> DeviceConfig {
    let conf = "/Users/shella/codez/mentos/config/Router.toml";
    let mut f = File::open(conf).unwrap();
    let mut contents = String::new();
    let toml_str = f.read_to_string(&mut contents)
        .expect("Something went wrong reading the file");

    let decoded: DeviceConfig = toml::from_str(&toml_str.to_string()).unwrap();
    return decoded;
}


