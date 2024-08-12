// Copyright (C) 2022 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use bytes::Bytes;

macro_rules! assert_eq_hex {
    ($left:expr, $right:expr) => {{
        use pretty_hex::config_hex;
        let left: &[u8] = &*$left;
        let right: &[u8] = &*$right;
        let cfg = pretty_hex::HexConfig {
            ..Default::default()
        };
        if left != right {
            panic!(
                "hex strings are not equal.\n\nleft: {}\n\nright: {}",
                config_hex(&left, cfg),
                config_hex(&right, cfg),
            );
        }
    }};
}

pub(crate) use assert_eq_hex;

pub(crate) fn init_logging() {
    let h = mylog::Builder::new()
        .set_format(
            ::std::env::var("MOONFIRE_FORMAT")
                .map_err(|_| ())
                .and_then(|s| mylog::Format::from_str(&s))
                .unwrap_or(mylog::Format::Google),
        )
        .set_spec(::std::env::var("MOONFIRE_LOG").as_deref().unwrap_or("info"))
        .build();
    let _ = h.install();
}

pub(crate) fn response(raw: &'static [u8]) -> rtsp_types::Response<Bytes> {
    let (msg, len) = rtsp_types::Message::parse(raw).unwrap();
    assert_eq!(len, raw.len());
    match msg {
        rtsp_types::Message::Response(r) => r.map_body(Bytes::from_static),
        _ => panic!("unexpected message type"),
    }
}
