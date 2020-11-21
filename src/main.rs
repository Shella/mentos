extern crate bufstream;
extern crate env_logger;
#[macro_use]
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
const TERMINATOR_WITH_NEWLINES: &[u8] = b"\n]]>]]>\n";

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

fn fetch(_all: bool) {
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

fn netconf(_hello: bool) {
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
        let _channel = junos_netconf_session(&session).expect("Unable to open channel");
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
    println!("get config reply: {:?}", String::from_utf8(config.clone()));
    parse_response(config);
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

    pub fn parse(&mut self) -> Result<Node, Error> {
        println!("+++ recursing!!!");

        let mut count = 0;
        let mut buf = vec![];
        let mut buf2 = vec![];
        let mut current_node = Node::map();

        loop {
            match self.reader.read_event(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    count += 1;
                    let mut name = String::from_utf8(e.name().to_vec()).unwrap();
                    println!("start: <{:?}>", name);
                    let parsed_child = self.parse()?;

                    match current_node {
                        Node::Map(ref mut map) => {
                            let node = match map.remove(&name) {
                                Some(node) => Node::List(match node {
                                    Node::List(mut l) => {
                                        l.push(parsed_child);
                                        l
                                    }
                                    other => vec![other, parsed_child],
                                }),
                                None => parsed_child,
                            };

                            map.insert(name, node);
                        }
                        other => panic!("wat: {:?}", other),
                    }
                }
                Ok(Event::End(ref e)) => {
                    let mut name = String::from_utf8(e.name().to_vec()).unwrap();
                    println!("end: </{:?}>", name);
                    println!("--- returning!!!");
                    return Ok(current_node);
                }
                Ok(Event::Text(e)) => {
                    println!("event text: {:?}", e);
                    // TODO: check that current_node is empty, and that the next event is Event::End
                    println!("--- returning!!!");

                    match self.reader.read_event(&mut buf2) {
                        Ok(Event::End(e)) => println!("text event end: {:?}", e),
                        _other => panic!("unexpected event at end of text: {:?}", e),
                    }

                    buf2.clear();
                    return Ok(Node::Value(
                        e.unescape_and_decode(&self.reader).expect("Error!"),
                    ));
                }
                Err(e) => panic!(
                    "Error at position {}: {:?}",
                    self.reader.buffer_position(),
                    e
                ),
                Ok(Event::Eof) => {
                    println!("event eof: {:?}", Event::Eof);
                    println!("--- returning!!!");
                    return Ok(current_node);
                }
                other => println!("event other: {:?}", other),
            }
            buf.clear();
        }
    }
}

#[derive(Debug)]
pub enum Node {
    List(Vec<Node>),
    Map(BTreeMap<String, Node>),
    Value(String),
}

impl Node {
    pub fn map() -> Node {
        Node::Map(BTreeMap::new())
    }

    pub fn insert(&mut self, name: String, child: Node) {
        if let Node::Map(ref mut map) = self {
            map.insert(name, child);
        } else {
            panic!("wat");
        }
    }

    pub fn get(&self, name: &str) -> Option<&Node> {
        match self {
            Node::Map(ref map) => map.get(name),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<&str> {
        match self {
            Node::Value(ref string) => Some(string),
            _ => None,
        }
    }
}

fn parse_response<C: Into<Vec<u8>>>(into_config: C) -> Result<Node, Error> {
    let config = into_config.into();

    let config_len = config
        .len()
        .checked_sub(TERMINATOR_WITH_NEWLINES.len())
        .unwrap();

    let terminator = &config[config_len..];
    if terminator != TERMINATOR_WITH_NEWLINES {
        bail!("unexpected terminator on message: {:?}", terminator);
    }

    let config_string = String::from_utf8(config[..config_len].to_vec()).unwrap();
    let mut reader = Reader::from_str(&config_string);
    reader.trim_text(true);
    let result = Parser::new(reader).parse();
    println!("parsed response: {:?}", result);
    result
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

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::Reader;

    const EXAMPLE_XML: &str = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/12.3R9/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1423750418" junos:changed-localtime="2015-02-12 14:13:38 UTC">
    <version>12.3R9.4</version>
    <system>
        <host-name>derp.switch</host-name>
        <time-zone>UTC</time-zone>
        <login>
            <user>
                <name>herp</name>
                <uid>1234</uid>
                <class>super-user</class>
            </user>
            <user>
                <name>derp</name>
                <uid>4321</uid>
                <class>super-user</class>
            </user>
        </login>
        <services>
            <ssh>
                <root-login>deny</root-login>
                <protocol-version>v2</protocol-version>
                <ciphers>aes256-ctr</ciphers>
                <ciphers>aes192-ctr</ciphers>
                <ciphers>aes128-ctr</ciphers>
                <macs>hmac-sha2-512</macs>
                <macs>hmac-sha2-256</macs>
                <key-exchange>group-exchange-sha2</key-exchange>
            </ssh>
            <netconf>
                <ssh>
                </ssh>
            </netconf>
            <dhcp>
                <traceoptions>
                    <file>
                        <filename>dhcp_logfile</filename>
                    </file>
                    <level>all</level>
                    <flag>
                        <name>all</name>
                    </flag>
                </traceoptions>
            </dhcp>
        </services>
        <syslog>
            <user>
                <name>*</name>
                <contents>
                    <name>any</name>
                    <emergency/>
                </contents>
            </user>
            <file>
                <name>messages</name>
                <contents>
                    <name>any</name>
                    <notice/>
                </contents>
                <contents>
                    <name>authorization</name>
                    <info/>
                </contents>
            </file>
            <file>
                <name>interactive-commands</name>
                <contents>
                    <name>interactive-commands</name>
                    <any/>
                </contents>
            </file>
        </syslog>
    </system>
    <chassis>
        <alarm>
            <management-ethernet>
                <link-down>ignore</link-down>
            </management-ethernet>
        </alarm>
        <auto-image-upgrade/>
    </chassis>
    <interfaces>
        <interface>
            <name>ge-0/0/0</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/1</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/2</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/3</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/4</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/5</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/6</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/7</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/8</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/9</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/10</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/0/11</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/1/0</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>ge-0/1/1</name>
            <unit>
                <name>0</name>
                <family>
                    <ethernet-switching>
                    </ethernet-switching>
                </family>
            </unit>
        </interface>
        <interface>
            <name>vlan</name>
            <unit>
                <name>0</name>
                <family>
                    <inet>
                        <address>
                            <name>10.0.0.2/24</name>
                        </address>
                    </inet>
                </family>
            </unit>
        </interface>
    </interfaces>
    <routing-options>
        <static>
            <route>
                <name>0.0.0.0/0</name>
                <next-hop>10.0.0.1</next-hop>
            </route>
        </static>
    </routing-options>
    <protocols>
        <igmp-snooping>
            <vlan>
                <name>all</name>
            </vlan>
        </igmp-snooping>
        <rstp>
        </rstp>
        <lldp>
            <interface>
                <name>all</name>
            </interface>
        </lldp>
        <lldp-med>
            <interface>
                <name>all</name>
            </interface>
        </lldp-med>
    </protocols>
    <ethernet-switching-options>
        <storm-control>
            <interface>
                <name>all</name>
            </interface>
        </storm-control>
    </ethernet-switching-options>
    <vlans>
        <vlan>
            <name>default</name>
            <l3-interface>vlan.0</l3-interface>
        </vlan>
    </vlans>
</configuration>
</rpc-reply>
]]>]]>
"#;

    #[test]
    fn parse_response_test() {
        let result = parse_response(EXAMPLE_XML).unwrap();

        if let Node::List(users) = result
            .get("rpc-reply")
            .unwrap()
            .get("configuration")
            .unwrap()
            .get("system")
            .unwrap()
            .get("login")
            .unwrap()
            .get("user")
            .unwrap()
        {
            let usernames: Vec<_> = users
                .iter()
                .map(|u| u.get("name").unwrap().value().unwrap())
                .collect();

            assert_eq!(usernames, ["herp", "derp"]);
        } else {
            panic!("users was not a list!")
        }
    }

}
