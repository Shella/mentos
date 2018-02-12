extern crate env_logger;
extern crate failure;
#[macro_use] extern crate serde_derive;
extern crate ssh2;
#[macro_use] extern crate structopt;
extern crate toml;
use failure::Error;
use ssh2::Session;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::TcpStream;

fn main() {
    env_logger::init();

    let device_config = read_toml().unwrap();
    let (_name, device) = device_config.devices.into_iter().next().unwrap();
    println!("RouterConfig: {:#?}", device);

    let ip = device.ip.as_ref().unwrap();
    let port = device.port.as_ref().unwrap();
    let user = device.user.as_ref().unwrap();
    let server = format!("{}:{}", ip, port);

    let mut session = ssh2_session().expect("Unable to create new session");
    println!("Connecting to server {}..", server);
    let tcp = TcpStream::connect(server).unwrap();
    session.handshake(&tcp).unwrap();
    session.userauth_agent(user).unwrap();

    assert!(session.authenticated());
    let banner = session.banner().unwrap();
    println!("Server Banner: {}", banner);

    if device.os.as_ref().unwrap() == "Junos OS" {
        let channel = junos_cmd_show_configuration(&session)
            .expect("Unable to open channel");
        println!("{}", channel.exit_status().unwrap());
    }
}

fn ssh2_session() -> Result<ssh2::Session, Error> {
    let sess = Session::new().unwrap();
    {
        let mut agent = sess.agent().unwrap();
        agent.connect().unwrap();
        agent.list_identities().unwrap();

        for identity in agent.identities() {
            let identity = identity.unwrap();
            println!("SSH Agent Identity: {}", identity.comment());
            let pubkey = identity.blob();
            println!("Key: {:?}", pubkey);
        }
    }

    Ok(sess)
}

fn junos_cmd_show_configuration(session: &Session) -> Result<ssh2::Channel, Error> {
    let mut channel = session.channel_session().unwrap();
    channel.exec("show configuration").unwrap();
    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    println!("{}", s);

    Ok(channel)
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

#[derive(StructOpt)]
#[structopt(name = "mentos", about = "the fresh maker")]
enum Mentos {
    #[structopt(name = "fetch")]
    Fetch {
        #[structopt(short = "all")]
        all: bool,
        input: Option<String>
    },
}