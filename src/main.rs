extern crate env_logger;
extern crate futures;
extern crate ring;
#[macro_use]
extern crate serde_derive;
extern crate ssh2;
extern crate thrussh;
extern crate thrussh_keys;
extern crate tokio_core;
extern crate toml;
use ssh2::Session as SessionClient;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;
use thrussh::*;
use thrussh::server::{Auth, Session};
use thrussh_keys::*;

#[derive(Clone)]
struct TestServer {}

impl server::Server for TestServer {
    type Handler = Self;
    fn new(&self, _: SocketAddr) -> Self {
        TestServer {}
    }
}

impl server::Handler for TestServer {
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
        let sh = TestServer {};
        println!("Test server running!");
        thrussh::server::run(config, "127.0.0.1:2225", sh);
    });

    let sess = SessionClient::new().unwrap();
    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();

    for identity in agent.identities() {
        let identity = identity.unwrap();
        println!("Identity: {}", identity.comment());
        let pubkey = identity.blob();
        println!("Key: {:?}", pubkey);
    }

    let device_config = read_toml();
    println!("{:#?}", device_config);
    //println!("user: {:#?}", device_config.user);
    //let agent_user = device_config.user.unwrap();

    //let tcp = TcpStream::connect(format!("{:?}:{:?}", device_config.ip, device_config.port)).unwrap();
    //let mut sess = SessionClient::new().unwrap();
    //sess.handshake(&tcp).unwrap();
    //sess.userauth_agent(&agent_user).unwrap();
    //assert!(sess.authenticated());

    std::mem::forget(t)
}

#[derive(Debug, Deserialize)]
struct Config {
    devices: HashMap<String, RouterConfig>,
}

#[derive(Debug, Deserialize)]
struct RouterConfig {
    hostname: Option<String>,
    ip: Option<String>,
    port: Option<u64>,
    os: Option<String>,
    user: Option<String>,
}

fn read_toml() -> Config {
    let conf = "/Users/shella/codez/mentos/config/Router.toml";
    let mut f = File::open(conf).unwrap();
    let mut contents = String::new();
     f.read_to_string(&mut contents)
        .expect("Something went wrong reading the file");

    print!("{}", contents);

    toml::from_str::<Config>(&contents.to_string()).unwrap()
}