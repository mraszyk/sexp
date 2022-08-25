use byteorder::{BigEndian, ReadBytesExt};
use core::pin::Pin;
use futures::future::{join_all, Future};
use ic_agent::{Agent, Certificate, ic_types::Principal, AgentError, lookup_value, hash_tree::Label};
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

fn get_paths(can: &Principal) -> Vec<Vec<Label> > {
  vec![get_path(can, "module_hash"), get_path(can, "controllers")]
}

#[tokio::main]
async fn main() {
  let batch_size = 5000;

  let args: Vec<String> = env::args().collect();
  let sub: Principal = Principal::from_text(&args[1]).unwrap();

  let agent = Agent::builder()
    .with_url("https://ic0.app/")
    .build()
    .unwrap();

  let nns_registry = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
  let subnets = agent.read_state_raw(vec![vec!["subnet".into()]], nns_registry, false).await.unwrap();
  agent.verify(&subnets, nns_registry, false).unwrap();
  let ranges = lookup_value(&subnets, vec!["subnet".into(), sub.as_slice().into(), "canister_ranges".into()]).unwrap();
  let ranges: Vec<(Principal, Principal)> = serde_cbor::from_slice(ranges).map_err(AgentError::InvalidCborData).unwrap();

  let mut calls: Vec<Pin<Box<dyn Future<Output = Result<Certificate<'_>, AgentError> > > > > = Vec::new();
  let mut canss : Vec<(Vec<Principal>, (Principal, Principal))> = Vec::new();
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
      let paths: Vec<Vec<Label> > = cans.iter().map(|c| get_paths(c)).flatten().collect();
      let response = agent.read_state_raw(paths, *from, false);
      calls.push(Box::pin(response));
      canss.push((cans, (*from, to)));
    }
  }
  let responses: Vec<Result<Certificate<'_>, AgentError> > = join_all(calls).await;
  for (response, (cans, (from, _))) in responses.iter().zip(canss.iter()) {
    let response = response.as_ref().unwrap();
    agent.verify(&response, *from, false).unwrap();
    for c in cans.iter() {
      match lookup_value(&response, get_path(c, "controllers")) {
        Ok(ctrls) => {
          let cbor: Value = serde_cbor::from_slice(ctrls).unwrap();
          let ctrls = match cbor {
            Value::Array(vec) => {
              vec.into_iter()
                .map(|elem: Value| {
                  match elem {
                    Value::Bytes(bytes) => {Principal::try_from(&bytes).unwrap().to_text()},
                    _ => {assert!(false); "".to_string()}
                  }
                })
              .collect::<Vec<String> >()
            },
            _ => {assert!(false); Vec::new()}
          };
          let hash = match lookup_value(&response, get_path(c, "module_hash")) {
            Ok(hash) => {format!("0x{}", hex::encode(&hash))}
            Err(_) => {"empty".to_string()}
          };
          println!("{}:\nControllers: {:?}\nModule hash: {}\n", c.to_text(), ctrls, hash);
        },
        Err(_) => {}
      }
    }
  }
}
