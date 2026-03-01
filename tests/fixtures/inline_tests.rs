fn real_code() -> i32 {
    42
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(real_code(), 42);
    }
}
