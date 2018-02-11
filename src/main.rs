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
use std::io::Read;


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
            "127.0.0.1:2222", config, None, self,

            |connection| {

                let mut key_file = std::fs::File::open("~/.ssh/id_ed25519").unwrap();
                let mut key = String::new();
                key_file.read_to_string(&mut key).unwrap();
                let key = load_secret_key(&key, None).unwrap();

                connection.authenticate_key("shella", key)
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
    // Starting the server thread.
    let t = std::thread::spawn(|| {
        let mut config = thrussh::server::Config::default();
        config.connection_timeout = Some(std::time::Duration::from_secs(600));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config.keys.push(thrussh_keys::key::KeyPair::generate(thrussh_keys::key::ED25519).unwrap());
        let config = Arc::new(config);
        let sh = H{};
        thrussh::server::run(config, "0.0.0.0:2222", sh);
    });

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut config = thrussh::client::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(600));
    let config = Arc::new(config);
    let sh = Client {};
    sh.run(config, "127.0.0.1:2222");

    // Kill the server thread after the client has ended.
    std::mem::forget(t)
}