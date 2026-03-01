fn loop_clone(items: &[String]) {
    for item in items {
        let owned = item.clone();
        drop(owned);
    }
}

fn while_clone(items: &[String]) {
    let mut i = 0;
    while i < items.len() {
        let owned = items[i].clone();
        drop(owned);
        i += 1;
    }
}

fn plain_loop_clone(s: &str) {
    loop {
        let owned = s.to_string();
        let cloned = owned.clone();
        drop(cloned);
        break;
    }
}

fn no_loop_clone(s: &String) -> String {
    s.clone()
}
