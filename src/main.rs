extern crate env_logger;
extern crate failure;
#[macro_use]
extern crate serde_derive;
extern crate ssh2;
extern crate toml;
use failure::Error;
use ssh2::Session as SessionClient;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::TcpStream;

fn main() {
    env_logger::init();

    let device_config = read_toml().unwrap();
    let (_name, device) = device_config.devices.into_iter().next().unwrap();
    println!("RouterConfig: {:#?}", device);
    let ip = device.ip.unwrap();
    let port = device.port.unwrap();
    let user = device.user.unwrap();

    let sess = SessionClient::new().unwrap();
    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();

    for identity in agent.identities() {
        let identity = identity.unwrap();
        println!("SSH Agent Identity: {}", identity.comment());
        let pubkey = identity.blob();
        println!("Key: {:?}", pubkey);
    }

    let server = format!("{}:{}", ip, port);
    println!("Connecting to server {}..", server);
    let tcp = TcpStream::connect(server).unwrap();
    let mut sess = SessionClient::new().unwrap();
    sess.handshake(&tcp).unwrap();
    sess.userauth_agent(&user).unwrap();
    assert!(sess.authenticated());
    let banner = sess.banner().unwrap();
    println!("Server Banner: {}", banner);

    let mut channel = sess.channel_session().unwrap();
    channel.exec("show configuration").unwrap();
    let mut s = String::new();
    channel.read_to_string(&mut s).unwrap();
    println!("{}", s);
    channel.wait_close();
    println!("{}", channel.exit_status().unwrap());
}

#[derive(Debug, Deserialize)]
struct Config {
    devices: HashMap<String, RouterConfig>,
}

#[derive(Debug, Deserialize)]
struct RouterConfig {
    hostname: Option<String>,
    ip: Option<String>,
    port: Option<String>,
    os: Option<String>,
    user: Option<String>,
}

fn read_toml() -> Result<Config, Error> {
    let conf = "/Users/shella/codez/mentos/config/Router.toml";
    let mut f = File::open(conf).unwrap();
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    Ok(toml::from_str::<Config>(&contents.to_string())?)
}