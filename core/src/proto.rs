//! Messages: signaling (via the rendezvous server, encrypted with the code key) and control
//! messages inside the tunnel. Plus the packet type ids used on the wire.

use serde::{Deserialize, Serialize};

// ---- tunnel packet types (first byte of the encrypted body) ----
pub const P_PUNCH: u8 = 1;
pub const P_PUNCH_ACK: u8 = 2;
pub const P_DATA: u8 = 3;
pub const P_PING: u8 = 4;
pub const P_PONG: u8 = 5;
pub const P_CTRL: u8 = 6;
pub const P_BYE: u8 = 7;
pub const P_FILL: u8 = 8;

/// Messages exchanged through the rendezvous server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t")]
pub enum SignalMsg {
    /// Client -> host: "I want to connect".
    #[serde(rename = "offer")]
    Offer {
        ver: u32,
        sid: String,
        ts: u64,
        name: String,
        dev: String,
        /// client identity public key (base64url)
        spk: String,
        /// client ephemeral public key (base64url)
        epk: String,
        cands: Vec<String>,
        /// topic where the host should publish its answer
        reply: String,
        /// "hard" if our NAT maps every destination to a new port (symmetric)
        #[serde(default)]
        nat: String,
        /// public ports seen by STUN
        #[serde(default)]
        ports: Vec<u16>,
    },
    /// Host -> client: "your request reached me" (sent before the user decides).
    #[serde(rename = "ack")]
    Ack { sid: String },
    /// Host -> client.
    #[serde(rename = "answer")]
    Answer {
        ver: u32,
        sid: String,
        ts: u64,
        ok: bool,
        #[serde(default)]
        reason: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        dev: String,
        #[serde(default)]
        spk: String,
        #[serde(default)]
        epk: String,
        #[serde(default)]
        cands: Vec<String>,
        /// first three octets of the tunnel subnet, e.g. [10, 213, 77]
        #[serde(default)]
        net: Vec<u8>,
        #[serde(default)]
        nat: String,
        #[serde(default)]
        ports: Vec<u16>,
    },
}

/// Control messages inside the tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t")]
pub enum Ctrl {
    /// Sent by both sides right after the tunnel is up.
    #[serde(rename = "hello")]
    Hello {
        name: String,
        app_ver: String,
        /// Host only: Sunshine's unique id, if known.
        #[serde(default)]
        host_uuid: String,
        /// Host only: whether the streaming host (Sunshine) is running.
        #[serde(default)]
        host_ready: bool,
    },
    /// Client asks the host to accept a Moonlight pairing PIN.
    #[serde(rename = "pair")]
    Pair { pin: String, name: String },
    #[serde(rename = "pair_result")]
    PairResult { ok: bool, #[serde(default)] msg: String },
    /// Client asks the host to blast filler traffic at the given rates (Mbit/s), `ms` each.
    #[serde(rename = "speed_req")]
    SpeedReq { steps: Vec<u32>, ms: u32 },
    /// Host reports how many filler packets it sent per step.
    #[serde(rename = "speed_done")]
    SpeedDone { sent: Vec<u32> },
    /// Client tells the host the stream started / ended (for the host's UI).
    #[serde(rename = "stream")]
    Stream { active: bool, #[serde(default)] info: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shapes() {
        let m = SignalMsg::Answer {
            ver: 1,
            sid: "a".into(),
            ts: 5,
            ok: false,
            reason: "busy".into(),
            name: String::new(),
            dev: String::new(),
            spk: String::new(),
            epk: String::new(),
            cands: vec![],
            net: vec![],
            nat: String::new(),
            ports: vec![],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"t\":\"answer\""));
        let back: SignalMsg = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
        // minimal declined answer parses thanks to defaults
        let d: SignalMsg =
            serde_json::from_str(r#"{"t":"answer","ver":1,"sid":"x","ts":1,"ok":false}"#).unwrap();
        assert!(matches!(d, SignalMsg::Answer { ok: false, .. }));
        let c: Ctrl = serde_json::from_str(r#"{"t":"pair","pin":"1234","name":"PC"}"#).unwrap();
        assert_eq!(c, Ctrl::Pair { pin: "1234".into(), name: "PC".into() });
    }
}
