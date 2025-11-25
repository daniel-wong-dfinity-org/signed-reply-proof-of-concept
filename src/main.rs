use base64::Engine;
use clap::Parser;
use ic_agent::{Agent, export::Principal};
use ic_certification::{Certificate, HashTree, LookupResult, SubtreeLookupResult};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write, stdin},
    time::Duration,
};

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    subcommand: Subcommand,
}

impl Args {
    async fn execute(self) {
        self.subcommand.execute().await;
    }
}

#[derive(clap::Subcommand)]
enum Subcommand {
    DownloadSignedReply(DownloadSignedReply),
    LoadSignedReplyFromFile(LoadSignedReplyFromFile),
}

impl Subcommand {
    async fn execute(self) {
        #[rustfmt::skip] // Keep alignment, because it strongly triggers the human brain.
        match self {
            Self::DownloadSignedReply     (ok) => ok.execute().await,
            Self::LoadSignedReplyFromFile (ok) => ok.execute(),
        };
    }
}

#[derive(clap::Parser)]
struct DownloadSignedReply {
    #[arg(long)]
    callee: Principal,

    #[arg(long)]
    method: String,

    #[arg(long)]
    arg_path: String,
}

impl DownloadSignedReply {
    async fn execute(self) {
        let Self {
            callee,
            method,
            arg_path,
        } = self;

        let arg = if arg_path == "-" {
            let mut arg = vec![];
            stdin().read_to_end(&mut arg).unwrap();
            arg
        } else {
            fs::read(arg_path).unwrap()
        };

        let signed_proposal = download_signed_proposal(callee, &method, arg).await;
        let signed_proposal = serde_cbor::to_vec(&signed_proposal).unwrap();

        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(&signed_proposal).unwrap();
        handle.flush().unwrap();

        eprintln!("👍 Done outputing the certificate from read_state to stdout.");
    }
}

#[derive(clap::Parser)]
struct LoadSignedReplyFromFile {
    #[arg(long)]
    signed_reply_path: String,
}

impl LoadSignedReplyFromFile {
    fn execute(self) {
        let Self { signed_reply_path } = self;

        let content = fs::read(&signed_reply_path).unwrap();
        let certificate = serde_cbor::from_slice::<Certificate>(&content).unwrap();
        let reply = verify_signed_proposal(certificate);
        let reply = reply
            .into_iter()
            .map(|element| format!("{:02X}", element))
            .collect::<String>();
        println!("{reply}");
    }
}

#[tokio::main]
async fn main() {
    Args::parse().execute().await;
}

async fn download_signed_proposal(
    callee: Principal,
    method_name: &str,
    arg: Vec<u8>,
) -> Certificate {
    let agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .unwrap();

    let (_reply, certificate): (Vec<u8>, Certificate) = agent
        .update(&callee, method_name)
        .with_arg(arg)
        .call()
        .and_wait()
        .await
        .unwrap();

    certificate
}

fn verify_signed_proposal(certificate: Certificate) -> Vec<u8> {
    let a_very_long_time = Duration::from_secs(365_250_000 * 24 * 60 * 60);

    let agent = Agent::builder()
        .with_url("https://ic0.app")
        .with_ingress_expiry(a_very_long_time)
        .build()
        .unwrap();

    // This is copied from ic-admin.
    const IC_ROOT_PUBLIC_KEY_BASE64: &str = r#"MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bWW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg=="#;
    // This is copied from rs/embedders.
    const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";
    assert_eq!(
        &base64::engine::general_purpose::STANDARD
            .decode(IC_ROOT_PUBLIC_KEY_BASE64)
            .unwrap(),
        IC_ROOT_KEY
    );
    assert_eq!(
        agent.read_root_key(),
        base64::engine::general_purpose::STANDARD
            .decode(IC_ROOT_PUBLIC_KEY_BASE64)
            .unwrap()
    );

    let _corrupt_root_key = {
        let mut result = agent.read_root_key();
        let last_index = result.len() - 1;
        result[last_index] = 0;
        result
    };
    // agent.set_root_key(corrupt_root_key);

    let governance_principal = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();

    agent
        .verify(&certificate, governance_principal)
        .unwrap_or_else(|err| {
            panic!("INPUT DOES NOT SEEM TO BE A GENUINE RESPONSE FROM THE CANISTER: {err:?}");
        });
    eprintln!();
    eprintln!(
        "👍 Certificate looks good. That is, we seem to have genuine data from\n\
         the ICP (presumably, a response from the Governance canister, but this\n\
         part has not been verified YET).",
    );
    eprintln!();

    /*
    let paths = certificate
        .tree
        .list_paths()
        .into_iter()
        .map(|path| {
            path
                .into_iter()
                .map(|segment| {
                    String::from_utf8_lossy(segment.as_bytes())
                        .into_owned()
                })
                .collect::<Vec<String>>()
                .join("    ")
        })
        .collect::<Vec<_>>();
    */

    let request_status = RequestStatus::try_from_tree(certificate.tree).unwrap();
    assert_eq!(&request_status.status, "replied");

    request_status.reply
}

#[derive(Debug, PartialEq, Eq, Default)] // DO NOT MERGE
struct RequestStatus {
    time: Vec<u8>,
    id: Vec<u8>,
    status: String,
    reply: Vec<u8>,
}

impl RequestStatus {
    fn try_from_tree(read_state_tree: HashTree) -> Result<Self, String> {
        let time = read_state_tree.lookup_path(vec![b"time".to_vec()]);
        let time = match time {
            LookupResult::Found(ok) => ok,
            _ => panic!("No time in input: {read_state_tree:?}"),
        };
        let time = time.to_vec();

        let request_status = match read_state_tree.lookup_subtree(vec![b"request_status"]) {
            SubtreeLookupResult::Found(ok) => ok,
            _ => panic!("request_status not in the HashTree: {read_state_tree:#?}"),
        };

        let request_ids = request_status
            .list_paths()
            .into_iter()
            .map(|path| path.first().unwrap().as_bytes().to_vec())
            .collect::<HashSet<Vec<u8>>>();
        assert_eq!(request_ids.len(), 1, "{request_ids:#?}");
        let request_id = request_ids.into_iter().next().unwrap();

        let status = request_status.lookup_path(vec![request_id.clone(), b"status".to_vec()]);
        let status = match status {
            LookupResult::Found(ok) => ok,
            _ => panic!("No status for request ID {request_id:?}."),
        };
        let status = String::from_utf8_lossy(status).into_owned();

        let reply = request_status.lookup_path(vec![request_id.clone(), b"reply".to_vec()]);
        let reply = match reply {
            LookupResult::Found(ok) => ok,
            _ => panic!("No reply for request ID {request_id:?}."),
        };
        let reply = reply.to_vec();

        Ok(Self {
            time,
            id: request_id,
            status,
            reply,
        })
    }
}
