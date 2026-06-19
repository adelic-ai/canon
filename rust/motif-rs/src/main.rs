//! motif-rs — a native interpreter for canon's detection IR (the hot-path emitter).
//!
//! Reads, on stdin, JSON `{"rules": [CompiledRule...], "events": [event...]}` and writes, on stdout,
//! `{"results": [[bool; n_events]; n_rules], "supported": [bool; n_rules]}`. It reproduces the Python
//! `field_matches` + condition-AST semantics: ASCII-only case-fold, Sigma glob (`*`/`?` → anchored DOTALL
//! regex, `\*`/`\?`/`\\` escapes, regex-metachar literals), the `eq/contains/startswith/endswith/all`
//! modifiers, keyword blocks (whole-event substring), and the boolean/quantifier condition AST. Clauses using
//! modifiers it does not yet implement (`re`/`cidr`/`gt|lt`/`windash`) mark the rule **unsupported** so the
//! agreement gate skips it rather than the emitter mis-firing. Event values arrive pre-string-coerced by the
//! Python bridge, so no coercion landmine here. Regexes are precompiled per rule, not per event.

use rayon::prelude::*;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::Instant;

const SUPPORTED_MODS: &[&str] = &["contains", "startswith", "endswith", "all", "eq"];

/// Sigma glob value → regex body (matches Python `glob_regex_body`): `*`→`.*`, `?`→`.`, `\*`/`\?`/`\\`→literal,
/// everything else regex-escaped.
fn glob_body(p: &str) -> String {
    let chars: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() && matches!(chars[i + 1], '*' | '?' | '\\') {
            out.push_str(&regex::escape(&chars[i + 1].to_string()));
            i += 2;
        } else if c == '*' {
            out.push_str(".*");
            i += 1;
        } else if c == '?' {
            out.push('.');
            i += 1;
        } else {
            out.push_str(&regex::escape(&c.to_string()));
            i += 1;
        }
    }
    out
}

/// Anchored, DOTALL regex for a case-folded pattern under an op (the modifier supplies the surrounding `.*`).
fn glob_regex(p_lower: &str, op: &str) -> Regex {
    let body = glob_body(p_lower);
    let wrapped = match op {
        "contains" => format!(".*{}.*", body),
        "startswith" => format!("{}.*", body),
        "endswith" => format!(".*{}", body),
        _ => body, // eq
    };
    Regex::new(&format!(r"(?s)\A(?:{})\z", wrapped)).unwrap()
}

fn op_of(mods: &[String]) -> &'static str {
    if mods.iter().any(|m| m == "endswith") { "endswith" }
    else if mods.iter().any(|m| m == "startswith") { "startswith" }
    else if mods.iter().any(|m| m == "contains") { "contains" }
    else { "eq" }
}

struct CClause {
    field: String,
    regexes: Vec<Regex>, // one per value
    match_all: bool,
}

struct CBlock {
    name: String,
    keyword: bool,
    maps: Vec<Vec<CClause>>,    // field-map: OR of maps, AND within a map
    kw_regexes: Vec<Regex>,     // keyword: contains-glob per keyword (matched against any field value)
}

struct CRule {
    blocks: Vec<CBlock>,
    condition: Value,
    supported: bool,
}

fn parse_clause(c: &Value) -> Option<CClause> {
    let field = c["field"].as_str()?.to_string();
    let mods: Vec<String> = c["mods"].as_array()?.iter().filter_map(|m| m.as_str().map(String::from)).collect();
    if !mods.iter().all(|m| SUPPORTED_MODS.contains(&m.as_str())) {
        return None; // unsupported modifier → caller marks the rule unsupported
    }
    let op = op_of(&mods);
    let regexes = c["values"].as_array()?.iter()
        .filter_map(|v| v.as_str())
        .map(|v| glob_regex(&v.to_ascii_lowercase(), op))
        .collect();
    Some(CClause { field, regexes, match_all: mods.iter().any(|m| m == "all") })
}

fn parse_rule(r: &Value) -> CRule {
    let mut supported = true;
    let mut blocks = Vec::new();
    if let Some(bs) = r["blocks"].as_array() {
        for b in bs {
            let name = b["name"].as_str().unwrap_or("").to_string();
            let kind = b["kind"].as_str().unwrap_or("and");
            if kind == "keyword" {
                let kw_regexes = b["keywords"].as_array().map(|ks| {
                    ks.iter().filter_map(|k| k.as_str()).map(|k| glob_regex(&k.to_ascii_lowercase(), "contains")).collect()
                }).unwrap_or_default();
                blocks.push(CBlock { name, keyword: true, maps: Vec::new(), kw_regexes });
            } else {
                let mut maps = Vec::new();
                if let Some(ms) = b["maps"].as_array() {
                    for m in ms {
                        let mut clauses = Vec::new();
                        if let Some(cs) = m.as_array() {
                            for c in cs {
                                match parse_clause(c) {
                                    Some(cc) => clauses.push(cc),
                                    None => supported = false,
                                }
                            }
                        }
                        maps.push(clauses);
                    }
                }
                blocks.push(CBlock { name, keyword: false, maps, kw_regexes: Vec::new() });
            }
        }
    }
    CRule { blocks, condition: r["condition"].clone(), supported }
}

fn field_str<'a>(event: &'a Map<String, Value>, field: &str) -> &'a str {
    event.get(field).and_then(|v| v.as_str()).unwrap_or("")
}

fn block_matches(b: &CBlock, event: &Map<String, Value>) -> bool {
    if b.keyword {
        // a keyword matches if it appears (contains-glob) in ANY field value
        return b.kw_regexes.iter().any(|rx| {
            event.values().any(|v| rx.is_match(&v.as_str().unwrap_or("").to_ascii_lowercase()))
        });
    }
    b.maps.iter().any(|m| {
        m.iter().all(|c| {
            let ev = field_str(event, &c.field).to_ascii_lowercase();
            if c.match_all {
                c.regexes.iter().all(|rx| rx.is_match(&ev))
            } else {
                c.regexes.iter().any(|rx| rx.is_match(&ev))
            }
        })
    })
}

fn glob_name(pat: &str, name: &str) -> bool {
    // simple case-sensitive fnmatch for block-name quantifier globs
    glob_regex(pat, "eq").is_match(name)
}

fn eval_ast(node: &Value, bm: &HashMap<&str, &CBlock>, names: &[&str], event: &Map<String, Value>) -> bool {
    let arr = match node.as_array() { Some(a) => a, None => return false };
    match arr[0].as_str().unwrap_or("") {
        "and" => arr[1].as_array().map_or(true, |ns| ns.iter().all(|n| eval_ast(n, bm, names, event))),
        "or" => arr[1].as_array().map_or(false, |ns| ns.iter().any(|n| eval_ast(n, bm, names, event))),
        "not" => !eval_ast(&arr[1], bm, names, event),
        "ref" => arr[1].as_str().and_then(|nm| bm.get(nm)).map_or(false, |b| block_matches(b, event)),
        "quant" => {
            let n = arr[1].as_i64();
            let pat = arr[2].as_str().unwrap_or("");
            let sel: Vec<&&str> = if pat == "them" { names.iter().collect() }
                else { names.iter().filter(|nm| glob_name(pat, nm)).collect() };
            let matched = sel.iter().filter(|nm| bm.get(***nm).map_or(false, |b| block_matches(b, event))).count();
            match n {
                None => !sel.is_empty() && matched == sel.len(),
                Some(k) => matched as i64 >= k,
            }
        }
        _ => false,
    }
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let v: Value = serde_json::from_str(&input).unwrap();

    let t_compile = Instant::now();
    let rules: Vec<CRule> = v["rules"].as_array().unwrap().iter().map(parse_rule).collect();
    let events: Vec<Map<String, Value>> = v["events"].as_array().unwrap().iter()
        .filter_map(|e| e.as_object().cloned()).collect();
    eprintln!("rust_compile_seconds {}", t_compile.elapsed().as_secs_f64());

    // parallel across rules (events are independent) — build each rule's block map once, then sweep events
    let t_eval = Instant::now();
    let (results, supported): (Vec<Vec<bool>>, Vec<bool>) = rules.par_iter().map(|rule| {
        if rule.supported {
            let bm: HashMap<&str, &CBlock> = rule.blocks.iter().map(|b| (b.name.as_str(), b)).collect();
            let names: Vec<&str> = rule.blocks.iter().map(|b| b.name.as_str()).collect();
            (events.iter().map(|e| eval_ast(&rule.condition, &bm, &names, e)).collect(), true)
        } else {
            (vec![false; events.len()], false)
        }
    }).unzip();
    eprintln!("rust_eval_seconds {}", t_eval.elapsed().as_secs_f64());

    let out = serde_json::json!({ "results": results, "supported": supported });
    io::stdout().write_all(out.to_string().as_bytes()).unwrap();
}
