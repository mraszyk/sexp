use byteorder::{BigEndian, ReadBytesExt};
use candid::Principal;
use core::pin::Pin;
use futures::future::{join_all, Future};
use ic_agent::{hash_tree::Label, lookup_value, Agent, AgentError, Certificate};
use serde_cbor::Value;
use std::env;

fn next_principal(princ: &Principal) -> Principal {
    let mut val = princ.as_slice().read_u64::<BigEndian>().unwrap();
    val += 1;
    let mut b: Vec<u8> = val.to_be_bytes().clone().into();
    let mut c: Vec<u8> = vec![1, 1];
    b.append(&mut c);
    Principal::from_slice(&b)
}

fn get_path(can: &Principal, attr: &str) -> Vec<Label> {
    vec!["canister".into(), can.into(), attr.into()]
}

fn get_paths(can: &Principal) -> Vec<Vec<Label>> {
    vec![get_path(can, "module_hash"), get_path(can, "controllers")]
}

#[tokio::main]
async fn main() {
    let batch_size = 20000;

    let args: Vec<String> = env::args().collect();
    let url = &args[1];
    let arg: Option<Principal> = if args.len() > 2 {
        Some(Principal::from_text(&args[2]).unwrap())
    } else {
        None
    };

    let agent = Agent::builder().with_url(url).build().unwrap();
    if url.starts_with("http://127.0.0.1:") {
        agent.fetch_root_key().await.unwrap();
    }

    let nns_registry = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    let subnets = agent
        .read_state_raw(vec![vec!["subnet".into()]], nns_registry)
        .await
        .unwrap();
    agent.verify(&subnets, nns_registry).unwrap();
    for p in subnets.tree.list_paths() {
        if p.len() == 3 && p[0] == "subnet".into() && p[2] == "canister_ranges".into() {
            let sub: Principal = Principal::from_slice(p[1].as_bytes());
            if match arg {
                None => false,
                Some(arg) => sub != arg,
            } {
                continue;
            };
            println!("Subnet: {:?}", sub.to_string());
            let ranges = lookup_value(
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

            let mut calls: Vec<Pin<Box<dyn Future<Output = Result<Certificate<'_>, AgentError>>>>> =
                Vec::new();
            let mut canss: Vec<(Vec<Principal>, (Principal, Principal))> = Vec::new();
            for (from, to) in ranges.iter() {
                let mut cur = from.clone();
                let to = next_principal(to);
                while cur != to {
                    let mut cans: Vec<Principal> = Vec::new();
                    let mut i = 0;
                    while cur != to && i < batch_size {
                        cans.push(cur);
                        cur = next_principal(&cur);
                        i += 1;
                    }
                    let paths: Vec<Vec<Label>> =
                        cans.iter().map(|c| get_paths(c)).flatten().collect();
                    let response = agent.read_state_raw(paths, *from);
                    calls.push(Box::pin(response));
                    canss.push((cans, (*from, to)));
                }
            }
            let responses: Vec<Result<Certificate<'_>, AgentError>> = join_all(calls).await;
            for (response, (cans, (from, _))) in responses.iter().zip(canss.iter()) {
                match response.as_ref() {
                    Err(e) => {
                        println!("{:?}", e);
                    }
                    Ok(response) => {
                        agent.verify(&response, *from).unwrap();
                        for c in cans.iter() {
                            match lookup_value(&response, get_path(c, "controllers")) {
                                Ok(ctrls) => {
                                    let cbor: Value = serde_cbor::from_slice(ctrls).unwrap();
                                    let ctrls = match cbor {
                                        Value::Array(vec) => vec
                                            .into_iter()
                                            .map(|elem: Value| match elem {
                                                Value::Bytes(bytes) => {
                                                    Principal::try_from(&bytes).unwrap().to_text()
                                                }
                                                _ => {
                                                    println!("Could not parse controllers!");
                                                    "".to_string()
                                                }
                                            })
                                            .collect::<Vec<String>>(),
                                        _ => {
                                            println!("Could not parse controllers!");
                                            Vec::new()
                                        }
                                    };
                                    let hash =
                                        match lookup_value(&response, get_path(c, "module_hash")) {
                                            Ok(hash) => {
                                                format!("0x{}", hex::encode(&hash))
                                            }
                                            Err(_) => "empty".to_string(),
                                        };
                                    println!(
                                        "{}:\nControllers: {:?}\nModule hash: {}\n",
                                        c.to_text(),
                                        ctrls,
                                        hash
                                    );
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
            }
        }
    }
}
