extern crate bufstream;
extern crate env_logger;
extern crate failure;
extern crate quick_xml;
#[macro_use]
extern crate serde_derive;
extern crate ssh2;
#[macro_use]
extern crate structopt;
extern crate toml;
use bufstream::BufStream;
use failure::Error;
use quick_xml::{Reader, Writer};
use ssh2::Session;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use structopt::StructOpt;

fn main() {
    env_logger::init();

    let mentos = Mentos::from_args();
    println!("{:?}", mentos);
    match mentos {
        Mentos::Fetch { all, .. } => fetch(all),
        Mentos::Netconf { hello, .. } => netconf(hello),
    }
}

fn get_device_config() -> RouterConfig {
    let device_config = read_toml().unwrap();
    let (_name, device) = device_config.devices.into_iter().next().unwrap();
    //println!("RouterConfig: {:#?}", device);
    device
}

fn fetch(all: bool) {
    let device = get_device_config();
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
        let channel = junos_cmd_show_configuration(&session).expect("Unable to open channel");
        let exit_status = channel.exit_status().unwrap();
        if exit_status != 0 {
            println!("Channel exit status: {}", exit_status);
        }
    }
}

fn netconf(hello: bool) {
    let device = get_device_config();
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
        let channel = junos_netconf_session(&session).expect("Unable to open channel");
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

struct Connection<'sess> {
    channel: BufStream<ssh2::Channel<'sess>>,
}

impl<'sess> Connection<'sess> {
    pub fn new(channel: BufStream<ssh2::Channel>) -> Connection{
        Connection{channel}
    }

    pub fn read(&mut self) -> Result<Vec<u8>, Error> {
        let mut xml = vec![];
        loop {
            let length = {
                let buffer = self.channel.fill_buf()?;
                xml.extend_from_slice(buffer);
                buffer.len()
            };
            self.channel.consume(length);
            if xml
                .windows(6)
                .position(|window| window == b"]]>]]>")
                .is_some()
                {
                   return Ok(xml)
                }
        }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        let len = self.channel.write(data)?;
        self.channel.flush()?;
        Ok(len)
    }
}

fn junos_netconf_session(session: &Session) -> Result<Connection, Error> {
    let mut channel = session.channel_session().unwrap();
    channel.shell().unwrap();
    let mut buf = BufStream::new(channel);
    let mut prompt = vec![];
    buf.read_until(b' ', &mut prompt)?;
    buf.write(b"netconf\n")?;
    buf.flush()?;
    let mut conn = Connection::new(buf);
    let hello_msg = conn.read()?;
    println!("{:?}", &hello_msg);
    junos_netconf_send_hello(&mut conn).unwrap();
    junos_netconf_get_config(&mut conn).unwrap();

    Ok(conn)
}

fn junos_netconf_send_hello(conn: &mut Connection) -> Result<(), Error> {
    let hello = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <capabilities>
                    <capability>urn:ietf:params:netconf:base:1.0</capability>
                    </capabilities>
                </hello>]]>]]>"#;
    conn.write(hello.as_bytes())?;
    Ok(())
}

fn junos_netconf_get_config(conn: &mut Connection) -> Result<usize, Error> {
    let get_config = r#"<rpc><get-configuration/></rpc>]]>]]>"#;
    let config_usize = conn.write(get_config.as_bytes())?;
    Ok(config_usize)
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
    let current_dir = env::current_dir().unwrap();
    let dir = current_dir.into_os_string().into_string().unwrap();
    let conf = "/config/Router.toml";
    let conf_path = format!("{}{}", dir, conf);
    let mut f = File::open(conf_path).unwrap();
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    Ok(toml::from_str::<Config>(&contents.to_string())?)
}

#[derive(Debug, StructOpt)]
#[structopt(name = "mentos", about = "the fresh maker")]
enum Mentos {
    #[structopt(name = "fetch")]
    Fetch {
        #[structopt(short = "a", long = "all")]
        all: bool,
    },
    #[structopt(name = "netconf")]
    Netconf {
        #[structopt(short = "h", long = "hello")]
        hello: bool,
    },
}
