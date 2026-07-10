//! Calico label selector language: parser + evaluator.
//!
//! Grammar (a faithful subset of upstream `libcalico-go/lib/selector`):
//!
//! ```text
//!   expr    := or
//!   or      := and ( "||" and )*
//!   and     := unary ( "&&" unary )*
//!   unary   := "!" unary | primary
//!   primary := "(" expr ")"
//!            | "all" "(" ")"
//!            | "has" "(" label ")"
//!            | label "==" string
//!            | label "!=" string
//!            | label "in"     "{" string ( "," string )* "}"
//!            | label "not" "in" "{" string ( "," string )* "}"
//! ```
//!
//! `label` is a bareword (letters, digits, `._-/`), `string` is single- or
//! double-quoted. Semantics match Calico: `k != v` and `k not in {...}` are true
//! when the label is absent.

use std::collections::BTreeMap;

/// A parsed label selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// `all()` — matches everything.
    All,
    /// `has(k)` — label `k` is present.
    Has(String),
    /// `k == "v"`.
    Equal(String, String),
    /// `k != "v"` (also true when `k` is absent).
    NotEqual(String, String),
    /// `k in {"a","b"}`.
    In(String, Vec<String>),
    /// `k not in {"a","b"}` (also true when `k` is absent).
    NotIn(String, Vec<String>),
    /// `!expr`.
    Not(Box<Selector>),
    /// `a && b`.
    And(Box<Selector>, Box<Selector>),
    /// `a || b`.
    Or(Box<Selector>, Box<Selector>),
}

/// A selector parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorError(pub String);

impl std::fmt::Display for SelectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "selector parse error: {}", self.0)
    }
}

impl std::error::Error for SelectorError {}

impl Selector {
    /// Parse a selector string.
    pub fn parse(input: &str) -> Result<Selector, SelectorError> {
        let tokens = tokenize(input)?;
        let mut p = Parser { tokens, pos: 0 };
        let sel = p.parse_or()?;
        if p.peek().is_some() {
            return Err(SelectorError(format!("trailing input at token {}", p.pos)));
        }
        Ok(sel)
    }

    /// Return a copy of this selector with every label **key** prefixed by
    /// `prefix`; values and structure are unchanged, and `all()` (which
    /// references no key) is returned as-is.
    ///
    /// This reproduces upstream `parser.PrefixVisitor`
    /// (`libcalico-go/lib/selector/parser/ast.go`), used to project a rule's
    /// `namespaceSelector` into the `pcns.` label namespace (namespace labels
    /// are surfaced onto endpoints under that prefix) — e.g. `k == 'v'` becomes
    /// `pcns.k == 'v'`.
    pub fn prefix_keys(&self, prefix: &str) -> Selector {
        match self {
            Selector::All => Selector::All,
            Selector::Has(k) => Selector::Has(format!("{prefix}{k}")),
            Selector::Equal(k, v) => Selector::Equal(format!("{prefix}{k}"), v.clone()),
            Selector::NotEqual(k, v) => Selector::NotEqual(format!("{prefix}{k}"), v.clone()),
            Selector::In(k, set) => Selector::In(format!("{prefix}{k}"), set.clone()),
            Selector::NotIn(k, set) => Selector::NotIn(format!("{prefix}{k}"), set.clone()),
            Selector::Not(e) => Selector::Not(Box::new(e.prefix_keys(prefix))),
            Selector::And(a, b) => Selector::And(
                Box::new(a.prefix_keys(prefix)),
                Box::new(b.prefix_keys(prefix)),
            ),
            Selector::Or(a, b) => Selector::Or(
                Box::new(a.prefix_keys(prefix)),
                Box::new(b.prefix_keys(prefix)),
            ),
        }
    }

    /// Evaluate the selector against a set of labels.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match self {
            Selector::All => true,
            Selector::Has(k) => labels.contains_key(k),
            Selector::Equal(k, v) => labels.get(k).map(|x| x == v).unwrap_or(false),
            Selector::NotEqual(k, v) => labels.get(k).map(|x| x != v).unwrap_or(true),
            Selector::In(k, set) => labels.get(k).map(|x| set.contains(x)).unwrap_or(false),
            Selector::NotIn(k, set) => labels.get(k).map(|x| !set.contains(x)).unwrap_or(true),
            Selector::Not(e) => !e.matches(labels),
            Selector::And(a, b) => a.matches(labels) && b.matches(labels),
            Selector::Or(a, b) => a.matches(labels) || b.matches(labels),
        }
    }
}

impl std::fmt::Display for Selector {
    /// Render a **canonical** string form of the selector.
    ///
    /// This is deterministic for a given parsed AST and is the basis for the
    /// stable IP-set id a rule selector hashes to (see
    /// [`crate::active_rules::ip_set_id`]). Set literals are sorted and
    /// de-duplicated so that `k in {"b","a"}` and `k in {"a","b"}` canonicalise
    /// identically; binary/negation operands are always parenthesised so the
    /// form is unambiguous. It is NOT guaranteed byte-identical to the input.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Selector::All => write!(f, "all()"),
            Selector::Has(k) => write!(f, "has({k})"),
            Selector::Equal(k, v) => write!(f, "{k} == {}", quote(v)),
            Selector::NotEqual(k, v) => write!(f, "{k} != {}", quote(v)),
            Selector::In(k, set) => write!(f, "{k} in {}", set_literal(set)),
            Selector::NotIn(k, set) => write!(f, "{k} not in {}", set_literal(set)),
            Selector::Not(e) => write!(f, "!({e})"),
            Selector::And(a, b) => write!(f, "({a}) && ({b})"),
            Selector::Or(a, b) => write!(f, "({a}) || ({b})"),
        }
    }
}

/// Quote a label value for the canonical form, escaping `\` and `"`.
fn quote(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Canonical set literal: sorted, de-duplicated, quoted values.
fn set_literal(set: &[String]) -> String {
    let mut items: Vec<&String> = set.iter().collect();
    items.sort();
    items.dedup();
    let joined = items
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{joined}}}")
}

// ---- Tokenizer -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    EqEq,
    NotEq,
    AndAnd,
    OrOr,
    Bang,
    Ident(String),
    Str(String),
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')
}

fn tokenize(input: &str) -> Result<Vec<Token>, SelectorError> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push(Token::LParen);
                i += 1;
            }
            ')' => {
                out.push(Token::RParen);
                i += 1;
            }
            '{' => {
                out.push(Token::LBrace);
                i += 1;
            }
            '}' => {
                out.push(Token::RBrace);
                i += 1;
            }
            ',' => {
                out.push(Token::Comma);
                i += 1;
            }
            '=' => {
                if chars.get(i + 1) == Some(&'=') {
                    out.push(Token::EqEq);
                    i += 2;
                } else {
                    return Err(SelectorError("expected '==' after '='".into()));
                }
            }
            '!' => {
                if chars.get(i + 1) == Some(&'=') {
                    out.push(Token::NotEq);
                    i += 2;
                } else {
                    out.push(Token::Bang);
                    i += 1;
                }
            }
            '&' => {
                if chars.get(i + 1) == Some(&'&') {
                    out.push(Token::AndAnd);
                    i += 2;
                } else {
                    return Err(SelectorError("expected '&&'".into()));
                }
            }
            '|' => {
                if chars.get(i + 1) == Some(&'|') {
                    out.push(Token::OrOr);
                    i += 2;
                } else {
                    return Err(SelectorError("expected '||'".into()));
                }
            }
            '\'' | '"' => {
                let quote = c;
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != quote {
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(SelectorError("unterminated string literal".into()));
                }
                out.push(Token::Str(chars[start..i].iter().collect()));
                i += 1; // consume closing quote
            }
            c if is_ident_char(c) => {
                let start = i;
                while i < chars.len() && is_ident_char(chars[i]) {
                    i += 1;
                }
                out.push(Token::Ident(chars[start..i].iter().collect()));
            }
            other => return Err(SelectorError(format!("unexpected character '{other}'"))),
        }
    }
    Ok(out)
}

// ---- Parser --------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Token) -> Result<(), SelectorError> {
        match self.next() {
            Some(ref t) if t == want => Ok(()),
            other => Err(SelectorError(format!("expected {want:?}, got {other:?}"))),
        }
    }

    fn parse_or(&mut self) -> Result<Selector, SelectorError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::OrOr)) {
            self.next();
            let right = self.parse_and()?;
            left = Selector::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Selector, SelectorError> {
        let mut left = self.parse_unary()?;
        while matches!(self.peek(), Some(Token::AndAnd)) {
            self.next();
            let right = self.parse_unary()?;
            left = Selector::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Selector, SelectorError> {
        if matches!(self.peek(), Some(Token::Bang)) {
            self.next();
            return Ok(Selector::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Selector, SelectorError> {
        match self.next() {
            Some(Token::LParen) => {
                let inner = self.parse_or()?;
                self.expect(&Token::RParen)?;
                Ok(inner)
            }
            Some(Token::Ident(word)) => self.parse_ident_expr(word),
            other => Err(SelectorError(format!("unexpected token {other:?}"))),
        }
    }

    /// A bareword begins one of: `all()`, `has(k)`, `k == v`, `k != v`,
    /// `k in {..}`, `k not in {..}`.
    fn parse_ident_expr(&mut self, word: String) -> Result<Selector, SelectorError> {
        match word.as_str() {
            "all" => {
                self.expect(&Token::LParen)?;
                self.expect(&Token::RParen)?;
                Ok(Selector::All)
            }
            "has" => {
                self.expect(&Token::LParen)?;
                let key = self.expect_ident()?;
                self.expect(&Token::RParen)?;
                Ok(Selector::Has(key))
            }
            // Otherwise `word` is a label key; the next token decides the op.
            _ => match self.next() {
                Some(Token::EqEq) => Ok(Selector::Equal(word, self.expect_str()?)),
                Some(Token::NotEq) => Ok(Selector::NotEqual(word, self.expect_str()?)),
                Some(Token::Ident(kw)) if kw == "in" => Ok(Selector::In(word, self.parse_set()?)),
                Some(Token::Ident(kw)) if kw == "not" => match self.next() {
                    Some(Token::Ident(kw2)) if kw2 == "in" => {
                        Ok(Selector::NotIn(word, self.parse_set()?))
                    }
                    other => Err(SelectorError(format!(
                        "expected 'in' after 'not', got {other:?}"
                    ))),
                },
                other => Err(SelectorError(format!(
                    "expected operator after label '{word}', got {other:?}"
                ))),
            },
        }
    }

    fn parse_set(&mut self) -> Result<Vec<String>, SelectorError> {
        self.expect(&Token::LBrace)?;
        let mut items = Vec::new();
        // Allow an empty set `{}`.
        if matches!(self.peek(), Some(Token::RBrace)) {
            self.next();
            return Ok(items);
        }
        loop {
            items.push(self.expect_str()?);
            match self.next() {
                Some(Token::Comma) => continue,
                Some(Token::RBrace) => break,
                other => {
                    return Err(SelectorError(format!(
                        "expected ',' or '}}' in set, got {other:?}"
                    )))
                }
            }
        }
        Ok(items)
    }

    fn expect_ident(&mut self) -> Result<String, SelectorError> {
        match self.next() {
            Some(Token::Ident(s)) => Ok(s),
            other => Err(SelectorError(format!("expected identifier, got {other:?}"))),
        }
    }

    fn expect_str(&mut self) -> Result<String, SelectorError> {
        match self.next() {
            Some(Token::Str(s)) => Ok(s),
            other => Err(SelectorError(format!(
                "expected string literal, got {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn all_matches_everything() {
        let s = Selector::parse("all()").unwrap();
        assert!(s.matches(&labels(&[])));
        assert!(s.matches(&labels(&[("a", "b")])));
    }

    #[test]
    fn equality_and_absence() {
        let s = Selector::parse("role == 'frontend'").unwrap();
        assert!(s.matches(&labels(&[("role", "frontend")])));
        assert!(!s.matches(&labels(&[("role", "backend")])));
        assert!(!s.matches(&labels(&[]))); // absent != match
    }

    #[test]
    fn not_equal_is_true_when_absent() {
        let s = Selector::parse("role != 'db'").unwrap();
        assert!(s.matches(&labels(&[("role", "web")])));
        assert!(s.matches(&labels(&[]))); // absent label matches !=
        assert!(!s.matches(&labels(&[("role", "db")])));
    }

    #[test]
    fn has_checks_presence() {
        let s = Selector::parse("has(tier)").unwrap();
        assert!(s.matches(&labels(&[("tier", "anything")])));
        assert!(!s.matches(&labels(&[("other", "x")])));
    }

    #[test]
    fn in_and_not_in_sets() {
        let s = Selector::parse("env in {'prod', 'staging'}").unwrap();
        assert!(s.matches(&labels(&[("env", "prod")])));
        assert!(!s.matches(&labels(&[("env", "dev")])));
        assert!(!s.matches(&labels(&[])));

        let n = Selector::parse("env not in {'prod'}").unwrap();
        assert!(n.matches(&labels(&[("env", "dev")])));
        assert!(n.matches(&labels(&[]))); // absent matches "not in"
        assert!(!n.matches(&labels(&[("env", "prod")])));
    }

    #[test]
    fn boolean_precedence_and_over_or() {
        // a || b && c  ==  a || (b && c)
        let s = Selector::parse("a == '1' || b == '1' && c == '1'").unwrap();
        // b=1,c=0 => (b&&c) false, a=0 => overall false
        assert!(!s.matches(&labels(&[("b", "1")])));
        // a=1 alone => true
        assert!(s.matches(&labels(&[("a", "1")])));
        // b=1,c=1 => true
        assert!(s.matches(&labels(&[("b", "1"), ("c", "1")])));
    }

    #[test]
    fn negation_and_parens() {
        let s = Selector::parse("!(role == 'db')").unwrap();
        assert!(s.matches(&labels(&[("role", "web")])));
        assert!(!s.matches(&labels(&[("role", "db")])));

        let s2 = Selector::parse("(a == '1' || b == '1') && c == '1'").unwrap();
        assert!(s2.matches(&labels(&[("a", "1"), ("c", "1")])));
        assert!(!s2.matches(&labels(&[("a", "1")]))); // missing c
    }

    #[test]
    fn kubernetes_style_label_keys() {
        let s = Selector::parse("projectcalico.org/namespace == 'kube-system'").unwrap();
        assert!(s.matches(&labels(&[("projectcalico.org/namespace", "kube-system")])));
    }

    #[test]
    fn double_quotes_accepted() {
        let s = Selector::parse("k == \"v\"").unwrap();
        assert!(s.matches(&labels(&[("k", "v")])));
    }

    #[test]
    fn canonical_display_is_stable_and_normalises_sets() {
        // Set order/dupes canonicalise identically.
        let a = Selector::parse("env in {'b', 'a', 'b'}").unwrap();
        let b = Selector::parse("env in {'a', 'b'}").unwrap();
        assert_eq!(a.to_string(), b.to_string());
        assert_eq!(a.to_string(), "env in {\"a\", \"b\"}");

        // Compound forms round-trip through parse to the same canonical string.
        let s = Selector::parse("!(a == '1') && b != '2'").unwrap();
        let reparsed = Selector::parse(&s.to_string()).unwrap();
        assert_eq!(s.to_string(), reparsed.to_string());
    }

    #[test]
    fn prefix_keys_prefixes_every_label_key() {
        // Brief vector: `a == 'x' && has(b)` prefixed with `pcns.` matches
        // `pcns.a == 'x' && has(pcns.b)`.
        let s = Selector::parse("a == 'x' && has(b)").unwrap();
        let p = s.prefix_keys("pcns.");
        assert_eq!(p, Selector::parse("pcns.a == 'x' && has(pcns.b)").unwrap());
        // Display round-trips: parse(display(p)) == p.
        assert_eq!(Selector::parse(&p.to_string()).unwrap(), p);
        // Evaluation follows the prefixed keys, not the originals.
        assert!(p.matches(&labels(&[("pcns.a", "x"), ("pcns.b", "1")])));
        assert!(!p.matches(&labels(&[("a", "x"), ("b", "1")])));
    }

    #[test]
    fn prefix_keys_covers_all_node_kinds_and_preserves_all_and_values() {
        // Every label-bearing node kind (In/NotEqual/NotIn/Has/Equal) gets its
        // key prefixed; `all()` (no key) and all values are unchanged. Mirrors
        // upstream `parser.PrefixVisitor`.
        let s = Selector::parse("!(k in {'v1','v2'}) || m != 'n' || has(h) || all()").unwrap();
        let p = s.prefix_keys("pcns.");
        let expected =
            Selector::parse("!(pcns.k in {'v1','v2'}) || pcns.m != 'n' || has(pcns.h) || all()")
                .unwrap();
        assert_eq!(p, expected);
        assert_eq!(p.to_string(), expected.to_string());
    }

    #[test]
    fn parse_errors() {
        assert!(Selector::parse("role ==").is_err()); // missing value
        assert!(Selector::parse("role = 'x'").is_err()); // single '='
        assert!(Selector::parse("has(").is_err()); // unterminated
        assert!(Selector::parse("'unterminated").is_err());
        assert!(Selector::parse("a == 'b' garbage").is_err()); // trailing
        assert!(Selector::parse("env not of {'x'}").is_err()); // 'not' without 'in'
    }
}
