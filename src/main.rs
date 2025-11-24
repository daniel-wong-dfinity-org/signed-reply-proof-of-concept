use ic_agent::{Agent, export::Principal};
use ic_certification::{Certificate, HashTree, LookupResult, SubtreeLookupResult};
use std::{collections::HashSet, fs, time::Duration};

#[tokio::main]
async fn main() {
    println!("⏳ Downloading reply...");
    let signed_proposal = download_signed_proposal().await;
    let signed_proposal = serde_cbor::to_vec(&signed_proposal).unwrap();
    fs::write("signed_proposal.cbor", &signed_proposal).unwrap();
    drop(signed_proposal);
    println!("👍 Successfully downloaded reply to signed_proposal.cbor.");
    println!();

    // 👆 Download and store.
    // 👇 Offline: load, verify, and unpack.

    println!("Loading reply from signed_proposal.cbor.");
    let signed_proposal = fs::read("signed_proposal.cbor").unwrap();
    let signed_proposal = serde_cbor::from_slice::<Certificate>(&signed_proposal).unwrap();
    let reply = verify_signed_proposal(signed_proposal);
    println!("{reply:?}");
}

async fn download_signed_proposal() -> Certificate {
    let agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .unwrap();

    let governance_principal = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();

    let (_reply, certificate): (Vec<u8>, Certificate) = agent
        .update(&governance_principal, "get_build_metadata")
        .with_arg(candid::encode_args(()).unwrap())
        .call()
        .and_wait()
        .await
        .unwrap();

    certificate
}

fn verify_signed_proposal(certificate: Certificate) -> (String,) {
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
    assert_eq!(&base64::decode(IC_ROOT_PUBLIC_KEY_BASE64).unwrap(), IC_ROOT_KEY);
    assert_eq!(agent.read_root_key(), base64::decode(IC_ROOT_PUBLIC_KEY_BASE64).unwrap());

    let corrupt_root_key = {
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
    println!();
    println!(
        "👍 Certificate looks good. That is, we seem to have genuine data from\n\
         the ICP (presumably, a response from the Governance canister, but this\n\
         part has not been verified YET).",
    );
    println!();

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

    candid::decode_args::<(String,)>(&request_status.reply).unwrap()
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
