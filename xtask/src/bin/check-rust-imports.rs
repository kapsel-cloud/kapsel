//! Check structural Rust import rules without compiling platform-specific source.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode},
};

use proc_macro2::Span;
use syn::{
    parse::Parser as _,
    punctuated::Punctuated,
    spanned::Spanned as _,
    visit::{self, Visit},
    Attribute, Item, ItemMod, ItemUse, Meta, Token, UseTree,
};

struct Source {
    text: String,
    syntax: syn::File,
}

#[allow(clippy::print_stderr)]
fn main() -> ExitCode {
    match run() {
        Ok(findings) if findings.is_empty() => ExitCode::SUCCESS,
        Ok(findings) => {
            for finding in findings {
                eprintln!("{finding}");
            }
            ExitCode::FAILURE
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<Vec<String>, String> {
    if env::args_os().len() != 1 {
        return Err("usage: check-rust-imports (from the checkout root)".into());
    }
    let prefix = git_command()
        .args(["rev-parse", "--show-prefix"])
        .output()
        .map_err(|error| format!("locate checkout root: {error}"))?;
    if !prefix.status.success() || prefix.stdout != b"\n" {
        return Err("run check-rust-imports from the Git checkout root".into());
    }
    let output = git_command()
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.rs",
        ])
        .output()
        .map_err(|error| format!("list Rust source: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files failed; run from the checkout root".into());
    }
    let listing = String::from_utf8(output.stdout)
        .map_err(|error| format!("Rust source paths must be UTF-8: {error}"))?;
    let mut sources = BTreeMap::new();
    for name in listing.split('\0').filter(|name| !name.is_empty()) {
        let path = PathBuf::from(name);
        if !path.is_file() {
            continue;
        }
        let text =
            fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let syntax = syn::parse_file(&text).map_err(|error| {
            let position = error.span().start();
            format!(
                "{}:{}:{}: cannot parse Rust: {error}",
                path.display(),
                position.line,
                position.column + 1
            )
        })?;
        sources.insert(path, Source { text, syntax });
    }
    Ok(check_sources(&sources))
}

fn git_command() -> Command {
    let mut git = Command::new("git");
    for (key, _) in env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            git.env_remove(key);
        }
    }
    git
}

// A file shared by test and production modules is checked as production. Unknown
// module ownership is also production: a test-like filename is not an exemption.
fn check_sources(sources: &BTreeMap<PathBuf, Source>) -> Vec<String> {
    let mut edges = BTreeMap::new();
    let mut referenced = BTreeSet::new();
    for (path, source) in sources {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let root = matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("lib.rs" | "main.rs" | "mod.rs")
        ) || matches!(
            parent.file_name().and_then(|name| name.to_str()),
            Some("bin" | "tests" | "examples" | "benches" | "fuzz_targets")
        );
        let directory = if root {
            parent.to_path_buf()
        } else {
            path.with_extension("")
        };
        let mut children = Vec::new();
        module_edges(
            &source.syntax.items,
            &directory,
            parent,
            false,
            sources,
            &mut children,
        );
        referenced.extend(children.iter().map(|(child, _)| child.clone()));
        edges.insert(path.clone(), children);
    }
    let mut contexts = BTreeMap::<PathBuf, BTreeSet<bool>>::new();
    let mut pending: Vec<_> = sources
        .keys()
        .filter(|path| {
            !referenced.contains(*path)
                || matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("lib.rs" | "main.rs")
                )
                || path.parent().is_some_and(|parent| {
                    matches!(
                        parent.file_name().and_then(|name| name.to_str()),
                        Some("bin" | "tests" | "examples" | "benches" | "fuzz_targets")
                    )
                })
        })
        .map(|path| (path.clone(), integration_test(path)))
        .collect();
    while let Some((path, inherited_test)) = pending.pop() {
        let test_scope = inherited_test || test_only(&sources[&path].syntax.attrs);
        if !contexts.entry(path.clone()).or_default().insert(test_scope) {
            continue;
        }
        for (child, child_test) in &edges[&path] {
            pending.push((child.clone(), test_scope || *child_test));
        }
    }
    let mut findings = Vec::new();
    for (path, source) in sources {
        let tests = contexts
            .get(path)
            .is_some_and(|scopes| scopes.contains(&true) && !scopes.contains(&false));
        let mut checker = Checker {
            path,
            source,
            tests,
            block_depth: 0,
            findings: &mut findings,
        };
        checker.visit_file(&source.syntax);
    }
    findings
}

fn integration_test(path: &Path) -> bool {
    for part in path.components() {
        if part == Component::Normal("src".as_ref()) {
            return false;
        }
        if part == Component::Normal("tests".as_ref()) {
            return true;
        }
    }
    false
}

fn normalized(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {},
            Component::ParentDir => {
                result.pop();
            },
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn module_edges(
    items: &[Item],
    directory: &Path,
    path_directory: &Path,
    tests: bool,
    sources: &BTreeMap<PathBuf, Source>,
    edges: &mut Vec<(PathBuf, bool)>,
) {
    for item in items {
        let Item::Mod(module) = item else { continue };
        let tests = tests || test_only(&module.attrs);
        let explicit = module.attrs.iter().find_map(|attribute| {
            let Meta::NameValue(value) = &attribute.meta else {
                return None;
            };
            if !value.path.is_ident("path") {
                return None;
            }
            let syn::Expr::Lit(expression) = &value.value else {
                return None;
            };
            let syn::Lit::Str(path) = &expression.lit else {
                return None;
            };
            Some(path_directory.join(path.value()))
        });
        if let Some((_, items)) = &module.content {
            let directory = explicit.unwrap_or_else(|| directory.join(module.ident.to_string()));
            module_edges(items, &directory, &directory, tests, sources, edges);
        } else {
            let candidates = explicit.map_or_else(
                || {
                    vec![
                        directory.join(format!("{}.rs", module.ident)),
                        directory.join(module.ident.to_string()).join("mod.rs"),
                    ]
                },
                |path| vec![path],
            );
            for child in candidates.iter().map(|path| normalized(path)) {
                if sources.contains_key(&child) {
                    edges.push((child, tests));
                }
            }
        }
    }
}

// Evaluate cfg with test=false and all other predicates unknown. In particular,
// any(test, feature="...") can be production, while all(test, ...) cannot.
fn production_cfg(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::List(list) => {
            let children = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .ok()?;
            if list.path.is_ident("not") && children.len() == 1 {
                return production_cfg(&children[0]).map(|value| !value);
            }
            let values: Vec<_> = children.iter().map(production_cfg).collect();
            if list.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.contains(&None) {
                    None
                } else {
                    Some(true)
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.contains(&None) {
                    None
                } else {
                    Some(false)
                }
            } else {
                None
            }
        },
        _ => None,
    }
}

fn test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if attribute.path().is_ident("test") {
            return true;
        }
        let Meta::List(list) = &attribute.meta else {
            return false;
        };
        list.path.is_ident("cfg")
            && syn::parse2::<Meta>(list.tokens.clone())
                .is_ok_and(|meta| production_cfg(&meta) == Some(false))
    })
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn anonymous_imports(tree: &UseTree) -> bool {
    match tree {
        UseTree::Rename(rename) => rename.rename == "_",
        UseTree::Path(path) => anonymous_imports(&path.tree),
        UseTree::Group(group) => group.items.iter().all(anonymous_imports),
        _ => false,
    }
}

fn literal_covers_line(tokens: proc_macro2::TokenStream, line: usize) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Literal(literal) => {
            let span = literal.span();
            span.start().line <= line && line <= span.end().line
        },
        proc_macro2::TokenTree::Group(group) => literal_covers_line(group.stream(), line),
        _ => false,
    })
}

struct Checker<'a> {
    path: &'a Path,
    source: &'a Source,
    tests: bool,
    block_depth: usize,
    findings: &'a mut Vec<String>,
}

impl Checker<'_> {
    fn report(&mut self, span: Span, rule: &str, message: &str) {
        let position = span.start();
        self.findings.push(format!(
            "{}:{}:{}: {rule}: {message}",
            self.path.display(),
            position.line,
            position.column + 1
        ));
    }

    fn local_exception(&self, span: Span) -> bool {
        let line = span.start().line;
        let reason = line
            .checked_sub(2)
            .and_then(|index| self.source.text.lines().nth(index))
            .and_then(|line| {
                line.trim()
                    .strip_prefix("// rust-imports: allow-local-use: ")
            });
        reason.is_some_and(|reason| !reason.trim().is_empty())
            && self
                .source
                .text
                .parse::<proc_macro2::TokenStream>()
                .is_ok_and(|tokens| !literal_covers_line(tokens, line - 1))
    }

    fn use_path(&mut self, tree: &UseTree, parents: usize) {
        match tree {
            UseTree::Path(path) => {
                let parents = if path.ident == "super" {
                    parents + 1
                } else {
                    0
                };
                if parents == 2 {
                    self.report(
                        path.ident.span(),
                        "multi-level-super",
                        "use an owning crate path",
                    );
                }
                self.use_path(&path.tree, parents);
            },
            UseTree::Group(group) => {
                for child in &group.items {
                    self.use_path(child, parents);
                }
            },
            UseTree::Name(name) if parents > 0 && name.ident == "super" => {
                self.report(
                    name.ident.span(),
                    "multi-level-super",
                    "use an owning crate path",
                );
            },
            UseTree::Rename(rename) if parents > 0 && rename.ident == "super" => {
                self.report(
                    rename.ident.span(),
                    "multi-level-super",
                    "use an owning crate path",
                );
            },
            _ => {},
        }
    }
}

impl<'ast> Visit<'ast> for Checker<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        let previous = self.tests;
        self.tests |= test_only(item_attributes(item));
        visit::visit_item(self, item);
        self.tests = previous;
    }

    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        let previous = self.block_depth;
        self.block_depth = 0;
        visit::visit_item_mod(self, module);
        self.block_depth = previous;
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attributes = match item {
            syn::ImplItem::Fn(item) => &item.attrs,
            syn::ImplItem::Const(item) => &item.attrs,
            syn::ImplItem::Type(item) => &item.attrs,
            syn::ImplItem::Macro(item) => &item.attrs,
            _ => return,
        };
        let previous = self.tests;
        self.tests |= test_only(attributes);
        visit::visit_impl_item(self, item);
        self.tests = previous;
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attributes = match item {
            syn::TraitItem::Fn(item) => &item.attrs,
            syn::TraitItem::Const(item) => &item.attrs,
            syn::TraitItem::Type(item) => &item.attrs,
            syn::TraitItem::Macro(item) => &item.attrs,
            _ => return,
        };
        let previous = self.tests;
        self.tests |= test_only(attributes);
        visit::visit_trait_item(self, item);
        self.tests = previous;
    }

    fn visit_expr_block(&mut self, expression: &'ast syn::ExprBlock) {
        let previous = self.tests;
        self.tests |= test_only(&expression.attrs);
        visit::visit_expr_block(self, expression);
        self.tests = previous;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.block_depth += 1;
        visit::visit_block(self, block);
        self.block_depth -= 1;
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.use_path(&item.tree, 0);
        if self.block_depth > 0
            && !self.tests
            && !anonymous_imports(&item.tree)
            && !self.local_exception(item.span())
        {
            self.report(
                item.span(),
                "block-local-use",
                "move named imports to module scope",
            );
        }
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path
            .segments
            .iter()
            .take_while(|segment| segment.ident == "super")
            .count()
            > 1
        {
            self.report(path.span(), "multi-level-super", "use an owning crate path");
        }
        visit::visit_path(self, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(files: &[(&str, &str)]) -> Result<Vec<String>, syn::Error> {
        let sources = files
            .iter()
            .map(|(path, text)| {
                Ok((
                    PathBuf::from(path),
                    Source {
                        text: (*text).into(),
                        syntax: syn::parse_file(text)?,
                    },
                ))
            })
            .collect::<Result<_, syn::Error>>()?;
        Ok(check_sources(&sources))
    }

    #[test]
    fn checks_real_paths_and_grouped_imports_not_comments_or_literals() -> Result<(), syn::Error> {
        let result = findings(&[(
            "src/lib.rs",
            r#"
            // super::super::Comment
            const TEXT: &str = "super::super::Literal";
            use super::{super::Type};
            use super::super;
            use super::{super as parent};
            fn f() { super::super::call(); }
        "#,
        )])?;
        assert_eq!(result.len(), 4);
        assert!(result
            .iter()
            .all(|message| message.contains("multi-level-super")));
        Ok(())
    }

    #[test]
    fn local_imports_allow_only_anonymous_leaves_or_a_reason() -> Result<(), syn::Error> {
        let result = findings(&[(
            "src/lib.rs",
            r#"
            fn f() {
                use std::{fmt::Write as _, io::Read as _};
                use external::{Trait as _, Type};
                // rust-imports: allow-local-use: scoped platform extension
                use external::Type;
                // rust-imports: allow-local-use:
                use external::Other;
                let text = "use external::NotAnImport;";
            }
        "#,
        )])?;
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|message| message.contains("block-local-use")));
        Ok(())
    }

    #[test]
    fn exception_text_inside_a_raw_literal_cannot_suppress_an_import() -> Result<(), syn::Error> {
        let result = findings(&[(
            "src/lib.rs",
            r##"
            fn f() {
                let text = r#"sample
                // rust-imports: allow-local-use: not a comment"#;
                use external::Type;
            }
        "##,
        )])?;
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[test]
    fn platform_scopes_are_checked_without_expanding_macros() -> Result<(), syn::Error> {
        let result = findings(&[(
            "src/lib.rs",
            r#"
            #[cfg(target_os = "linux")] fn f() { use external::Type; }
            macro_rules! fixture { () => { fn f() { use external::Type; } }; }
        "#,
        )])?;
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[test]
    fn test_context_follows_inline_and_external_modules_not_names() -> Result<(), syn::Error> {
        let result = findings(&[
            (
                "src/lib.rs",
                r#"
                #[cfg(all(test, target_os = "linux"))]
                #[path = "fixtures.rs"] mod fixtures;
                #[cfg(test)] mod inline { mod child; }
                mod misleading_tests;
            "#,
            ),
            (
                "src/fixtures.rs",
                "mod child; fn f() { use external::Type; }",
            ),
            ("src/fixtures/child.rs", "fn f() { use external::Type; }"),
            ("src/inline/child.rs", "fn f() { use external::Type; }"),
            ("src/misleading_tests.rs", "fn f() { use external::Type; }"),
            ("tests/contract.rs", "fn f() { use external::Type; }"),
        ])?;
        assert_eq!(result.len(), 1);
        assert!(result[0].starts_with("src/misleading_tests.rs:"));
        Ok(())
    }

    #[test]
    fn production_references_override_test_directory_and_root_reuse() -> Result<(), syn::Error> {
        let result = findings(&[
            (
                "src/lib.rs",
                r#"#[path = "../tests/shared.rs"] mod shared;
                fn f() { use external::Type; }"#,
            ),
            ("tests/shared.rs", "fn f() { use external::Type; }"),
            (
                "tests/reuse.rs",
                r#"#[cfg(test)] #[path = "../src/lib.rs"] mod library;"#,
            ),
        ])?;
        assert_eq!(result.len(), 2);
        Ok(())
    }

    #[test]
    fn test_methods_and_blocks_do_not_exempt_production_neighbors() -> Result<(), syn::Error> {
        let result = findings(&[(
            "src/lib.rs",
            r"
            struct Fixture;
            impl Fixture {
                #[cfg(test)] fn test_helper() { use external::Type; }
                fn production() { use external::Type; }
            }
            trait Contract {
                #[cfg(test)] fn test_helper() { use external::Type; }
                fn production() { use external::Type; }
            }
            fn blocks() {
                #[cfg(test)] { use external::Type; }
                { use external::Type; }
            }
        ",
        )])?;
        assert_eq!(result.len(), 3);
        Ok(())
    }

    #[test]
    fn mixed_cfg_and_shared_modules_remain_production() -> Result<(), syn::Error> {
        let result = findings(&[
            (
                "src/lib.rs",
                r#"
                #[cfg(test)] #[path = "shared.rs"] mod tests;
                #[path = "shared.rs"] mod production;
                #[cfg(any(test, feature = "fixture"))]
                fn f() { use external::Type; }
                #[test] fn fixture() { use external::Type; }
            "#,
            ),
            ("src/shared.rs", "fn f() { use external::Type; }"),
        ])?;
        assert_eq!(result.len(), 2);
        Ok(())
    }

    #[test]
    fn module_imports_inside_blocks_and_test_paths_keep_distinct_rules() -> Result<(), syn::Error> {
        let result = findings(&[(
            "tests/contract.rs",
            r"
            fn f() {
                mod nested { use external::Type; }
                use super::super::Type;
            }
        ",
        )])?;
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("multi-level-super"));
        Ok(())
    }
}
