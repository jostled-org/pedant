use ring::aead;

fn has_pem() {
    let _key = "-----BEGIN PRIVATE KEY-----\nbase64data\n-----END PRIVATE KEY-----";
}
