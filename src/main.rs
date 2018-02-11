extern crate thrussh;
extern crate thrussh_keys;
extern crate futures;
extern crate tokio_core;
extern crate env_logger;
extern crate ssh2;
extern crate ring;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;
use thrussh::*;
use thrussh::server::{Auth, Session};
use thrussh_keys::*;
use ssh2::Session as SessionClient;

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
    type FutureUnit = futures::Finished<(Self, thrussh::server::Session), Self::Error>;
    type FutureBool = futures::Finished<(Self, thrussh::server::Session, bool), Self::Error>;

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
    fn data(self, channel: ChannelId, data: &[u8], mut session: thrussh::server::Session) -> Self::FutureUnit {
        println!("data on channel {:?}: {:?}", channel, std::str::from_utf8(data));
        session.data(channel, None, data);
        futures::finished((self, session))
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

    let sess = SessionClient::new().unwrap();
    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();

    for identity in agent.identities() {
        let identity = identity.unwrap();
        println!("{}", identity.comment());
        let pubkey = identity.blob();
        println!("{:?}", pubkey);
    }

    let tcp = TcpStream::connect("127.0.0.1:2225").unwrap();
    let mut sess = SessionClient::new().unwrap();
    sess.handshake(&tcp).unwrap();
    sess.userauth_agent("shella").unwrap();
    assert!(sess.authenticated());

    let device_config = read_toml();
    println!("{:#?}", device_config);

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

    toml::from_str::<DeviceConfig>(&toml_str.to_string()).unwrap()
}