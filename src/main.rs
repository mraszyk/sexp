use candid::Principal;
use ic_agent::{lookup_value, Agent, AgentError};
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let url = &args[1];
    let arg: Option<Principal> = if args.len() > 2 {
        Some(Principal::from_text(&args[2]).unwrap())
    } else {
        None
    };

    let agent = Agent::builder().with_url(url).build().unwrap();
    if !url.starts_with("https://ic0.app") && !url.starts_with("https://icp-api.io") {
        println!("######################################################################");
        println!("Fetching the root key from /api/v2/status! Do not use with IC mainnet!");
        println!("######################################################################");
        println!("\n\n");
        agent.fetch_root_key().await.unwrap();
    }

    let nns_registry = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    let subnets = agent
        .read_state_raw(vec![vec!["subnet".into()]], nns_registry)
        .await
        .unwrap();
    agent.verify(&subnets, nns_registry).unwrap();
    for p in subnets.tree.list_paths() {
        if p.len() == 3 && p[0] == "subnet".into() && p[2] == "public_key".into() {
            let sub: Principal = Principal::from_slice(p[1].as_bytes());
            if match arg {
                None => false,
                Some(arg) => sub != arg,
            } {
                continue;
            };
            let pk = lookup_value::<Vec<Vec<u8>>, _>(
                &subnets,
                vec!["subnet".into(), sub.as_slice().into(), "public_key".into()],
            )
            .unwrap();
            let ranges = lookup_value::<Vec<Vec<u8>>, _>(
                &subnets,
                vec![
                    "subnet".into(),
                    sub.as_slice().into(),
                    "canister_ranges".into(),
                ],
            )
            .unwrap();
            let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(ranges)
                .map_err(AgentError::InvalidCborData)
                .unwrap();
            println!("Subnet: {:?}", sub.to_string());
            println!("Public key: 0x{}", hex::encode(pk));
            println!(
                "Canister ranges: {:?}",
                ranges
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect::<Vec<_>>()
            );
            println!("********");
        }
    }
}
