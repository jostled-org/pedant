struct SourceData {
    raw: String,
}

struct Processed {
    value: String,
}

fn convert() -> Processed {
    let src = SourceData { raw: "hello".into() };
    Processed { value: src.raw }
}
