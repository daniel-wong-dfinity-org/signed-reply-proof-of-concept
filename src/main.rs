use ic_agent::{Agent, export::Principal};
use ic_certification::{Certificate, HashTree, LookupResult, SubtreeLookupResult};
use std::{collections::HashSet, fs};

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
    let agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .unwrap();

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
