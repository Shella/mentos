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
use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use ssh2::Session;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use structopt::StructOpt;

const TERMINATOR: &[u8] = b"]]>]]>";

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
    pub fn new(channel: BufStream<ssh2::Channel>) -> Connection {
        Connection { channel }
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
                .position(|window| window == TERMINATOR)
                .is_some()
            {
                return Ok(xml);
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
    println!("{:?}", String::from_utf8(hello_msg));
    let hello = junos_netconf_send_hello(&mut conn).unwrap();
    println!("hello: {}", hello);
    let config = junos_netconf_get_config(&mut conn).unwrap();
    parse_config(&config);
    println!("get config: {:?}", String::from_utf8(config));
    junos_netconf_close_session(&mut conn).unwrap();
    Ok(conn)
}

fn junos_netconf_send_hello(conn: &mut Connection) -> Result<usize, Error> {
    let hello = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <capabilities>
                    <capability>urn:ietf:params:netconf:base:1.0</capability>
                    </capabilities>
                </hello>]]>]]>"#;
    let hello_usize = conn.write(hello.as_bytes())?;
    Ok(hello_usize)
}

fn junos_netconf_close_session(conn: &mut Connection) -> Result<usize, Error> {
    let close_session = r#"<rpc><close-session/></rpc>]]>]]>"#;
    let close_usize = conn.write(close_session.as_bytes())?;
    Ok(close_usize)
}

fn junos_netconf_get_config(conn: &mut Connection) -> Result<Vec<u8>, Error> {
    let get_config = r#"<rpc><get-configuration/></rpc>]]>]]>"#;
    conn.write(get_config.as_bytes())?;
    conn.read()
}

struct Parser<'a> {
    reader: Reader<&'a [u8]>,
}

impl<'a> Parser<'a> {
    pub fn new(reader: Reader<&'a [u8]>) -> Parser {
       Parser { reader }
    }

    pub fn parse_node(&mut self, current_node: &mut Node) {
        let mut count = 0;
        let mut txt = vec![];
        let mut buf = vec![];
        loop {
            match self.reader.read_event(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    count += 1;
                    println!("event start: {:?}", e);
                    println!("elem names: {:?}", String::from_utf8(e.name().to_vec()));
                }
                Ok(Event::Text(e)) => {
                    txt.push(e.unescape_and_decode(&self.reader).expect("Error!"));
                    println!("event text: {:?}", e);
                },
                Err(e) => panic!("Error at position {}: {:?}", self.reader.buffer_position(), e),
                Ok(Event::Eof) => {
                    println!("event eof: {:?}", Event::Eof);
                    break;

                }
                other => println!("other: {:?}", other)
            }
            buf.clear();
        }
        println!("Text events: {:?}", txt);
    }

}

struct Node(BTreeMap<String, Node>);

impl Node {
    pub fn new() -> Node {
        Node (BTreeMap::new())
    }


}

fn parse_config(config: &Vec<u8>) -> () {
    let config_string = String::from_utf8(config.to_vec()).unwrap();
    let mut reader = Reader::from_str(&config_string);
    reader.trim_text(true);

    let mut root_node = Node::new();
    let mut parser = Parser::new(reader);
    parser.parse_node(&mut root_node);



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
