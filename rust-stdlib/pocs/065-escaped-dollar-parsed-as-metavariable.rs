// Bug: collect_meta_vars in proc_macro::quote treats `$$ident` as metavariable
//      `$ident` because it scans every `$` punct followed by an Ident.
// Expected: `$$` is the documented literal-dollar escape and must not introduce a
//      metavariable for the following ident.
// Observed: pre-patch scanner records `var` from `$$var`.
// Build/run: rustc 065-escaped-dollar-parsed-as-metavariable.rs -o /tmp/poc065 && /tmp/poc065

#[derive(Clone, Debug, PartialEq)]
enum Tok { Punct(char), Ident(String), Group(Vec<Tok>) }

fn collect_meta_vars_buggy(stream: Vec<Tok>) -> Vec<String> {
    let mut out = Vec::new();
    fn helper(stream: Vec<Tok>, out: &mut Vec<String>) {
        let mut iter = stream.into_iter().peekable();
        while let Some(tree) = iter.next() {
            match &tree {
                Tok::Punct(c) if *c == '$' => {
                    if let Some(Tok::Ident(id)) = iter.peek() {
                        out.push(id.clone());
                        iter.next();
                    }
                }
                Tok::Group(inner) => helper(inner.clone(), out),
                _ => {}
            }
        }
    }
    helper(stream, &mut out);
    out
}

fn main() {
    let stream = vec![
        Tok::Group(vec![
            Tok::Punct('$'),
            Tok::Ident("x".to_string()),
            Tok::Punct('$'),
            Tok::Punct('$'),
            Tok::Ident("var".to_string()),
        ]),
    ];
    let meta = collect_meta_vars_buggy(stream);
    assert_eq!(meta, vec!["x".to_string(), "var".to_string()]);
    println!("triggered: collected metavars = {:?} (expected only [\"x\"])", meta);
}
