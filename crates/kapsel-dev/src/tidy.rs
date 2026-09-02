//! Repository-local Rust documentation hygiene checks.
//!
//! Hard rules cover objective rustdoc structure that compiler tooling does not express.

use std::{
    env,
    ffi::OsStr,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use syn::{
    spanned::Spanned, Attribute, Expr, Fields, ImplItem, Item, Lit, Meta, TraitItem, Visibility,
};

const HEADING_ORDER: &[(&str, usize)] = &[
    ("Errors", 0),
    ("Panics", 1),
    ("Safety", 2),
    ("Cancellation safety", 3),
    ("Performance", 4),
    ("Complexity", 4),
    ("Platform-specific behavior", 5),
    ("Examples", 6),
];
const HEADING_NAME: &str = "rustdoc-heading-name";
const HEADING_ORDER_RULE: &str = "rustdoc-heading-order";
const HEADING_DUPLICATE: &str = "rustdoc-heading-duplicate";
const SECTION_EMPTY: &str = "rustdoc-section-empty";
const SAFETY_SECTION: &str = "rustdoc-safety-section";
const EXAMPLE_FENCE: &str = "rustdoc-example-fence";
const EXAMPLE_UNWRAP: &str = "rustdoc-example-unwrap";
const EXAMPLE_PARSE: &str = "rustdoc-example-parse";
const DYNAMIC_DOC: &str = "rustdoc-dynamic-content";
const SOURCE_PARSE: &str = "rustdoc-source-parse";

#[derive(Clone, Debug, Eq, PartialEq)]
struct Finding {
    rule: &'static str,
    path: PathBuf,
    line_number: usize,
    message: String,
}

impl Finding {
    fn new(
        rule: &'static str,
        path: &Path,
        line_number: usize,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            path: path.to_path_buf(),
            line_number,
            message: message.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}: error[{}]: {}",
            self.path.display(),
            self.line_number,
            self.rule,
            self.message
        )
    }
}

#[derive(Debug)]
struct DocumentedItem {
    line_number: usize,
    is_unsafe: bool,
    has_dynamic_doc: bool,
    lines: Vec<(usize, String)>,
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    line_number: usize,
    content: Vec<(usize, String)>,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{error}");
            ExitCode::FAILURE
        },
    }
}

fn run(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<(), String> {
    run_at(Path::new("."), arguments)
}

fn run_at(
    root: &Path,
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<(), String> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().and_then(|value| value.into_string().ok());
    if arguments.next().is_some() || command.as_deref() != Some("tidy") {
        return Err("usage: kapsel-tidy tidy".into());
    }
    run_tidy(root)
}

fn run_tidy(root: &Path) -> Result<(), String> {
    let findings = collect_findings(root)?;
    if findings.is_empty() {
        let _ = writeln!(io::stdout().lock(), "tidy: OK");
        return Ok(());
    }
    report_findings(&findings);
    Err(format!("tidy: {} error(s)", findings.len()))
}

fn report_findings(findings: &[Finding]) {
    let stderr = io::stderr();
    let mut stderr = stderr.lock();
    for finding in findings {
        let _ = writeln!(stderr, "{finding}");
    }
}

fn collect_findings(root: &Path) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    walk_rust_sources(root, &mut findings)?;
    findings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.line_number.cmp(&right.line_number))
            .then(left.rule.cmp(right.rule))
    });
    Ok(findings)
}

fn walk_rust_sources(path: &Path, findings: &mut Vec<Finding>) -> Result<(), String> {
    if should_skip(path) {
        return Ok(());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        let entries = fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
            walk_rust_sources(&entry.path(), findings)?;
        }
    } else if metadata.is_file() && path.extension() == Some(OsStr::new("rs")) {
        let text =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        check_hard_rules(path, &text, findings);
    }
    Ok(())
}

fn should_skip(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(".git" | "target" | ".tmp")
        )
    })
}

fn check_hard_rules(path: &Path, text: &str, findings: &mut Vec<Finding>) {
    let items = match documented_public_items(text) {
        Ok(items) => items,
        Err(error) => {
            findings.push(Finding::new(
                SOURCE_PARSE,
                path,
                error.span().start().line,
                format!("Rust source could not be parsed for tidy inspection: {error}"),
            ));
            return;
        },
    };
    for item in items {
        if item.has_dynamic_doc {
            findings.push(Finding::new(
                DYNAMIC_DOC,
                path,
                item.line_number,
                "public rustdoc must use literal content so tidy can inspect it",
            ));
        }
        let sections = sections(&item);
        check_heading_names(path, &sections, findings);
        check_heading_order(path, &sections, findings);
        check_duplicate_headings(path, &sections, findings);
        check_empty_sections(path, &sections, findings);
        check_safety_section(path, &item, &sections, findings);
        check_examples(path, &sections, findings);
    }
}

fn documented_public_items(text: &str) -> Result<Vec<DocumentedItem>, syn::Error> {
    let file = syn::parse_file(text)?;
    let mut documented = Vec::new();
    let file_span = file
        .attrs
        .first()
        .map_or_else(Span::call_site, Spanned::span);
    push_documented(&file.attrs, file_span, false, &mut documented);
    collect_items(&file.items, &mut documented);
    Ok(documented)
}

fn collect_items(items: &[Item], documented: &mut Vec<DocumentedItem>) {
    for item in items {
        match item {
            Item::Const(item) if is_public(&item.vis) => {
                push_documented(&item.attrs, item.span(), false, documented);
            },
            Item::Enum(item) if is_public(&item.vis) => {
                push_documented(&item.attrs, item.span(), false, documented);
                for variant in &item.variants {
                    push_documented(&variant.attrs, variant.span(), false, documented);
                    collect_fields(&variant.fields, true, documented);
                }
            },
            Item::Fn(item) if is_public(&item.vis) => {
                push_documented(
                    &item.attrs,
                    item.span(),
                    matches!(item.sig.safety, syn::Safety::Unsafe(_)),
                    documented,
                );
            },
            Item::Mod(item) => {
                if is_public(&item.vis) {
                    push_documented(&item.attrs, item.span(), false, documented);
                }
                if let Some((_, items)) = &item.content {
                    collect_items(items, documented);
                }
            },
            Item::Static(item) if is_public(&item.vis) => {
                push_documented(&item.attrs, item.span(), false, documented);
            },
            Item::Struct(item) if is_public(&item.vis) => {
                push_documented(&item.attrs, item.span(), false, documented);
                collect_fields(&item.fields, false, documented);
            },
            Item::Trait(item) if is_public(&item.vis) => {
                push_documented(
                    &item.attrs,
                    item.span(),
                    item.unsafety.is_some(),
                    documented,
                );
                for trait_item in &item.items {
                    match trait_item {
                        TraitItem::Const(item) => {
                            push_documented(&item.attrs, item.span(), false, documented);
                        },
                        TraitItem::Fn(item) => push_documented(
                            &item.attrs,
                            item.span(),
                            matches!(item.sig.safety, syn::Safety::Unsafe(_)),
                            documented,
                        ),
                        TraitItem::Type(item) => {
                            push_documented(&item.attrs, item.span(), false, documented);
                        },
                        TraitItem::Macro(_) | TraitItem::Verbatim(_) | _ => {},
                    }
                }
            },
            Item::Type(item) if is_public(&item.vis) => {
                push_documented(&item.attrs, item.span(), false, documented);
            },
            Item::Union(item) if is_public(&item.vis) => {
                push_documented(&item.attrs, item.span(), false, documented);
                for field in &item.fields.named {
                    if is_public(&field.vis) {
                        push_documented(&field.attrs, field.span(), false, documented);
                    }
                }
            },
            Item::Impl(item) => {
                for impl_item in &item.items {
                    match impl_item {
                        ImplItem::Const(item) if is_public(&item.vis) => {
                            push_documented(&item.attrs, item.span(), false, documented);
                        },
                        ImplItem::Fn(item) if is_public(&item.vis) => push_documented(
                            &item.attrs,
                            item.span(),
                            matches!(item.sig.safety, syn::Safety::Unsafe(_)),
                            documented,
                        ),
                        ImplItem::Type(item) if is_public(&item.vis) => {
                            push_documented(&item.attrs, item.span(), false, documented);
                        },
                        _ => {},
                    }
                }
            },
            _ => {},
        }
    }
}

fn collect_fields(fields: &Fields, inherited_public: bool, documented: &mut Vec<DocumentedItem>) {
    for field in fields {
        if inherited_public || is_public(&field.vis) {
            push_documented(&field.attrs, field.span(), false, documented);
        }
    }
}

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

fn push_documented(
    attributes: &[Attribute],
    span: Span,
    is_unsafe: bool,
    documented: &mut Vec<DocumentedItem>,
) {
    let (lines, has_dynamic_doc) = doc_attribute_lines(attributes);
    if lines.is_empty() && !has_dynamic_doc {
        return;
    }
    documented.push(DocumentedItem {
        line_number: span.start().line,
        is_unsafe,
        has_dynamic_doc,
        lines,
    });
}

fn doc_attribute_lines(attributes: &[Attribute]) -> (Vec<(usize, String)>, bool) {
    let mut lines = Vec::new();
    let mut has_dynamic_doc = false;
    for attribute in attributes {
        if !attribute.path().is_ident("doc") {
            continue;
        }
        let Meta::NameValue(name_value) = &attribute.meta else {
            if matches!(&attribute.meta, Meta::List(list) if list.tokens.to_string() == "hidden") {
                continue;
            }
            has_dynamic_doc = true;
            continue;
        };
        let Expr::Lit(expression) = &name_value.value else {
            has_dynamic_doc = true;
            continue;
        };
        let Lit::Str(value) = &expression.lit else {
            has_dynamic_doc = true;
            continue;
        };
        let start = attribute.span().start().line;
        for (offset, line) in value.value().lines().enumerate() {
            lines.push((
                start + offset,
                line.strip_prefix(' ').unwrap_or(line).to_owned(),
            ));
        }
        if value.value().is_empty() {
            lines.push((start, String::new()));
        }
    }
    (lines, has_dynamic_doc)
}

fn sections(item: &DocumentedItem) -> Vec<Section> {
    let mut sections = Vec::<Section>::new();
    let mut fence = None::<(char, usize)>;
    for (line_number, line) in &item.lines {
        if let Some((marker, length)) = fence {
            if fence_closes(line, marker, length) {
                fence = None;
            }
            if let Some(section) = sections.last_mut() {
                section.content.push((*line_number, line.clone()));
            }
        } else if let Some(opening) = fence_opens(line) {
            fence = Some((opening.marker, opening.length));
            if let Some(section) = sections.last_mut() {
                section.content.push((*line_number, line.clone()));
            }
        } else if let Some(name) = line.strip_prefix("# ") {
            sections.push(Section {
                name: name.to_owned(),
                line_number: *line_number,
                content: Vec::new(),
            });
        } else if let Some(section) = sections.last_mut() {
            section.content.push((*line_number, line.clone()));
        }
    }
    sections
}

struct FenceOpening<'a> {
    marker: char,
    length: usize,
    info: &'a str,
}

fn fence_opens(line: &str) -> Option<FenceOpening<'_>> {
    let spaces = line.bytes().take_while(|byte| *byte == b' ').count();
    if spaces > 3 {
        return None;
    }
    let line = &line[spaces..];
    let marker = line.chars().next()?;
    if !matches!(marker, '`' | '~') {
        return None;
    }
    let length = line
        .chars()
        .take_while(|character| *character == marker)
        .count();
    if length < 3 {
        return None;
    }
    let info = line[length..].trim();
    if marker == '`' && info.contains('`') {
        return None;
    }
    Some(FenceOpening {
        marker,
        length,
        info,
    })
}

fn fence_closes(line: &str, marker: char, opening_length: usize) -> bool {
    let spaces = line.bytes().take_while(|byte| *byte == b' ').count();
    if spaces > 3 {
        return false;
    }
    let line = &line[spaces..];
    let length = line
        .chars()
        .take_while(|character| *character == marker)
        .count();
    length >= opening_length && line[length..].trim().is_empty()
}

fn heading_order(name: &str) -> Option<usize> {
    HEADING_ORDER
        .iter()
        .find_map(|(heading, order)| (*heading == name).then_some(*order))
}

fn check_heading_names(path: &Path, sections: &[Section], findings: &mut Vec<Finding>) {
    for section in sections {
        if heading_order(&section.name).is_none() {
            findings.push(Finding::new(
                HEADING_NAME,
                path,
                section.line_number,
                format!("unsupported level-one heading `# {}`", section.name),
            ));
        }
    }
}

fn check_heading_order(path: &Path, sections: &[Section], findings: &mut Vec<Finding>) {
    let mut previous = None;
    for section in sections {
        let Some(order) = heading_order(&section.name) else {
            continue;
        };
        if previous.is_some_and(|previous| order < previous) {
            findings.push(Finding::new(
                HEADING_ORDER_RULE,
                path,
                section.line_number,
                format!("`# {}` is out of canonical order", section.name),
            ));
        }
        previous = Some(order);
    }
}

fn check_duplicate_headings(path: &Path, sections: &[Section], findings: &mut Vec<Finding>) {
    let mut names = Vec::<&str>::new();
    let mut cost_section_seen = false;
    for section in sections {
        let duplicate = names.contains(&section.name.as_str())
            || (matches!(section.name.as_str(), "Performance" | "Complexity") && cost_section_seen);
        if duplicate {
            findings.push(Finding::new(
                HEADING_DUPLICATE,
                path,
                section.line_number,
                format!("duplicate contract section `# {}`", section.name),
            ));
        }
        if matches!(section.name.as_str(), "Performance" | "Complexity") {
            cost_section_seen = true;
        }
        names.push(&section.name);
    }
}

fn check_empty_sections(path: &Path, sections: &[Section], findings: &mut Vec<Finding>) {
    for section in sections {
        if !section
            .content
            .iter()
            .any(|(_, line)| !line.trim().is_empty())
        {
            findings.push(Finding::new(
                SECTION_EMPTY,
                path,
                section.line_number,
                format!("`# {}` must not be empty", section.name),
            ));
        }
    }
}

fn check_safety_section(
    path: &Path,
    item: &DocumentedItem,
    sections: &[Section],
    findings: &mut Vec<Finding>,
) {
    let safety = sections.iter().find(|section| section.name == "Safety");
    match (item.is_unsafe, safety) {
        (true, None) => findings.push(Finding::new(
            SAFETY_SECTION,
            path,
            item.line_number,
            "unsafe public API requires `# Safety`",
        )),
        (false, Some(section)) => findings.push(Finding::new(
            SAFETY_SECTION,
            path,
            section.line_number,
            "safe public API must not use `# Safety`",
        )),
        (true, Some(_)) | (false, None) => {},
    }
}

fn check_examples(path: &Path, sections: &[Section], findings: &mut Vec<Finding>) {
    let Some(examples) = sections.iter().find(|section| section.name == "Examples") else {
        return;
    };
    let mut rust_fence_seen = false;
    let mut fence = None::<(char, usize)>;
    let mut in_rust_fence = false;
    let mut rust_lines = Vec::<(usize, String)>::new();
    for (line_number, line) in &examples.content {
        if let Some((marker, length)) = fence {
            if fence_closes(line, marker, length) {
                if in_rust_fence {
                    check_example_unwraps(path, &rust_lines, findings);
                }
                rust_lines.clear();
                fence = None;
                in_rust_fence = false;
            } else if in_rust_fence {
                rust_lines.push((*line_number, rustdoc_code_line(line)));
            }
        } else if let Some(opening) = fence_opens(line) {
            fence = Some((opening.marker, opening.length));
            in_rust_fence = rustdoc_fence_is_rust(opening.info);
            rust_fence_seen |= in_rust_fence;
        }
    }
    if fence.is_some() && in_rust_fence {
        check_example_unwraps(path, &rust_lines, findings);
    }
    if !rust_fence_seen {
        findings.push(Finding::new(
            EXAMPLE_FENCE,
            path,
            examples.line_number,
            "`# Examples` requires a Rust doctest fence",
        ));
    }
}

fn rustdoc_fence_is_rust(info: &str) -> bool {
    if info.is_empty() {
        return true;
    }
    info.split(',').all(|token| {
        let token = token.trim();
        matches!(
            token,
            "rust" | "no_run" | "compile_fail" | "should_panic" | "ignore"
        ) || token.starts_with("ignore-")
            || matches!(
                token,
                "edition2015" | "edition2018" | "edition2021" | "edition2024" | "standalone_crate"
            )
            || is_rust_error_code(token)
            || (token.starts_with('{') && token.ends_with('}'))
    })
}

fn is_rust_error_code(token: &str) -> bool {
    token.len() == 5
        && token.starts_with('E')
        && token[1..].bytes().all(|byte| byte.is_ascii_digit())
}

fn rustdoc_code_line(line: &str) -> String {
    line.strip_prefix("##")
        .or_else(|| line.strip_prefix("# "))
        .unwrap_or(line)
        .to_owned()
}

fn check_example_unwraps(path: &Path, lines: &[(usize, String)], findings: &mut Vec<Finding>) {
    if lines.is_empty() {
        return;
    }
    let code = lines
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let Ok(tokens) = code.parse::<TokenStream>() else {
        findings.push(Finding::new(
            EXAMPLE_PARSE,
            path,
            lines[0].0,
            "Rust doctest fence could not be tokenized for tidy inspection",
        ));
        return;
    };
    let mut forbidden_lines = Vec::new();
    collect_forbidden_calls(tokens, &mut forbidden_lines);
    for parsed_line in forbidden_lines {
        let code_line = parsed_line.saturating_sub(1);
        let line_number = lines
            .get(code_line)
            .map_or(lines[0].0, |(line_number, _)| *line_number);
        findings.push(Finding::new(
            EXAMPLE_UNWRAP,
            path,
            line_number,
            "copyable example must use explicit failure handling instead of unwrap/expect",
        ));
    }
}

fn collect_forbidden_calls(tokens: TokenStream, lines: &mut Vec<usize>) {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if let TokenTree::Group(group) = token {
            collect_forbidden_calls(group.stream(), lines);
        }
        let TokenTree::Ident(identifier) = token else {
            continue;
        };
        if !matches!(identifier.to_string().as_str(), "unwrap" | "expect") {
            continue;
        }
        let function_definition = matches!(
            index.checked_sub(1).and_then(|previous| tokens.get(previous)),
            Some(TokenTree::Ident(previous)) if previous == "fn"
        );
        let call = matches!(
            tokens.get(index + 1),
            Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis
        );
        if call && !function_definition {
            lines.push(identifier.span().start().line);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::{collect_findings, run_at};

    static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn canonical_sections_have_no_hard_findings() -> Result<(), String> {
        let fixture = Fixture::new("canonical")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "/// Applies one request.\n",
                "///\n",
                "/// # Errors\n",
                "///\n",
                "/// Returns an error when persistence fails.\n",
                "///\n",
                "/// # Cancellation safety\n",
                "///\n",
                "/// Cancellation leaves recoverable durable state.\n",
                "///\n",
                "/// # Examples\n",
                "///\n",
                "/// ```\n",
                "/// # fn main() -> Result<(), Box<dyn std::error::Error>> {\n",
                "/// apply()?;\n",
                "/// # Ok(())\n",
                "/// # }\n",
                "/// ```\n",
                "pub async fn apply() -> Result<(), Error> { todo!() }\n",
            ),
        )?;

        let findings = collect_findings(fixture.path())?;

        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
        Ok(())
    }

    #[test]
    fn heading_rules_report_stable_codes() -> Result<(), String> {
        let fixture = Fixture::new("headings")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "/// Applies one request.\n",
                "///\n",
                "/// # Example\n",
                "/// text\n",
                "/// # Panics\n",
                "/// panic\n",
                "/// # Errors\n",
                "/// error\n",
                "/// # Errors\n",
                "pub fn apply() {}\n",
            ),
        )?;

        let codes = hard_codes(fixture.path())?;

        assert!(codes.contains(&"rustdoc-heading-name"));
        assert!(codes.contains(&"rustdoc-heading-order"));
        assert!(codes.contains(&"rustdoc-heading-duplicate"));
        assert!(codes.contains(&"rustdoc-section-empty"));
        Ok(())
    }

    #[test]
    fn safety_and_example_rules_report_stable_codes() -> Result<(), String> {
        let fixture = Fixture::new("safety_examples")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "/// Applies one request.\n",
                "///\n",
                "/// # Safety\n",
                "/// caller obligation\n",
                "/// # Examples\n",
                "/// ```text\n",
                "/// apply().unwrap();\n",
                "/// ```\n",
                "pub fn apply() {}\n",
                "/// Applies an unsafe request.\n",
                "pub unsafe fn apply_unsafe() {}\n",
            ),
        )?;

        let codes = hard_codes(fixture.path())?;

        assert!(codes.contains(&"rustdoc-safety-section"));
        assert!(codes.contains(&"rustdoc-example-fence"));
        Ok(())
    }

    #[test]
    fn attribute_block_and_trait_docs_are_checked() -> Result<(), String> {
        let fixture = Fixture::new("doc_forms")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "#[doc = \"Applies one request.\\n\\n# Error\\n\\nfailure\"]\n",
                "pub fn attribute() {}\n",
                "/** Applies one request.\n\n# Panic\n\npanic\n*/\n",
                "pub fn block() {}\n",
                "/// Applies one request.\n",
                "pub trait Apply {\n",
                "    /// Applies one trait request.\n",
                "    ///\n",
                "    /// # Perf\n",
                "    /// cost\n",
                "    fn apply(&self);\n",
                "}\n",
            ),
        )?;

        let findings = collect_findings(fixture.path())?;
        let heading_findings = findings
            .iter()
            .filter(|finding| finding.rule == "rustdoc-heading-name")
            .count();

        assert_eq!(heading_findings, 3);
        Ok(())
    }

    #[test]
    fn malformed_source_is_a_hard_finding() -> Result<(), String> {
        let fixture = Fixture::new("malformed_source")?;
        fixture.write("src/lib.rs", "pub fn broken( {\n")?;

        let codes = hard_codes(fixture.path())?;

        assert!(codes.contains(&"rustdoc-source-parse"));
        Ok(())
    }

    #[test]
    fn crate_and_dynamic_docs_are_checked() -> Result<(), String> {
        let fixture = Fixture::new("crate_dynamic")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "#![doc = \"Crate.\\n\\n# Perf\\n\\ncost\"]\n",
                "#[doc = include_str!(\"public.md\")]\n",
                "pub fn dynamic() {}\n",
            ),
        )?;

        let codes = hard_codes(fixture.path())?;

        assert!(codes.contains(&"rustdoc-heading-name"));
        assert!(codes.contains(&"rustdoc-dynamic-content"));
        Ok(())
    }

    #[test]
    fn hidden_public_docs_remain_statically_inspectable() -> Result<(), String> {
        let fixture = Fixture::new("hidden_public_docs")?;
        fixture.write(
            "src/lib.rs",
            "/// Fixed hidden bridge.\n#[doc(hidden)]\npub fn hidden_bridge() {}\n",
        )?;

        let codes = hard_codes(fixture.path())?;

        assert!(!codes.contains(&"rustdoc-dynamic-content"));
        Ok(())
    }

    #[test]
    fn all_public_member_shapes_are_checked() -> Result<(), String> {
        let fixture = Fixture::new("public_members")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "/// Surface.\n",
                "pub struct Surface {\n",
                "    /// Field.\n",
                "    /// # Perf\n",
                "    /// cost\n",
                "    pub field: u8,\n",
                "}\n",
                "/// State.\n",
                "pub enum State {\n",
                "    /// Variant.\n",
                "    /// # Perf\n",
                "    /// cost\n",
                "    First,\n",
                "    Second {\n",
                "        /// Variant field.\n",
                "        /// # Perf\n",
                "        /// cost\n",
                "        value: u8,\n",
                "    },\n",
                "}\n",
                "/// Contract.\n",
                "pub trait Contract {\n",
                "    /// Constant.\n",
                "    /// # Perf\n",
                "    /// cost\n",
                "    const LIMIT: usize;\n",
                "    /// Output.\n",
                "    /// # Perf\n",
                "    /// cost\n",
                "    type Output;\n",
                "}\n",
                "impl Surface {\n",
                "    /// Method.\n",
                "    /// # Perf\n",
                "    /// cost\n",
                "    pub fn method(&self) {}\n",
                "}\n",
            ),
        )?;

        let findings = collect_findings(fixture.path())?;
        let heading_findings = findings
            .iter()
            .filter(|finding| finding.rule == "rustdoc-heading-name")
            .count();

        assert_eq!(heading_findings, 6);
        Ok(())
    }

    #[test]
    fn rustdoc_modifiers_and_non_calls_are_allowed() -> Result<(), String> {
        let fixture = Fixture::new("rustdoc_modifiers")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "/// Applies one request.\n",
                "///\n",
                "/// # Examples\n",
                "///   ````rust,edition2021,standalone_crate,{.copyable}\n",
                "/// let message = \"value.unwrap()\";\n",
                "/// // value.expect(\"reason\");\n",
                "///   ````\n",
                "pub fn apply() {}\n",
            ),
        )?;

        let findings = collect_findings(fixture.path())?;

        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
        Ok(())
    }

    #[test]
    fn unwrap_in_rust_example_is_rejected() -> Result<(), String> {
        let fixture = Fixture::new("unwrap")?;
        fixture.write(
            "src/lib.rs",
            concat!(
                "/// Applies one request.\n",
                "///\n",
                "/// # Examples\n",
                "/// ```\n",
                "/// apply().unwrap();\n",
                "/// assert_eq!(result.expect(\"reason\"), expected);\n",
                "/// Result::unwrap(result);\n",
                "/// ```\n",
                "pub fn apply() {}\n",
            ),
        )?;

        let findings = collect_findings(fixture.path())?;
        let unwrap_findings = findings
            .iter()
            .filter(|finding| finding.rule == "rustdoc-example-unwrap")
            .count();
        assert_eq!(unwrap_findings, 3);
        Ok(())
    }

    #[test]
    fn only_tidy_command_is_accepted() -> Result<(), String> {
        let fixture = Fixture::new("commands")?;

        assert_eq!(run_at(fixture.path(), ["tidy".into()]), Ok(()));
        assert_eq!(
            run_at(fixture.path(), ["style-audit".into()]),
            Err("usage: kapsel-tidy tidy".into())
        );
        Ok(())
    }

    fn hard_codes(root: &Path) -> Result<Vec<&'static str>, String> {
        Ok(collect_findings(root)?
            .iter()
            .map(|finding| finding.rule)
            .collect())
    }

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Result<Self, String> {
            let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("kapsel-tidy-{name}-{}-{id}", std::process::id()));
            if root.exists() {
                fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
            }
            fs::create_dir_all(&root).map_err(|error| error.to_string())?;
            Ok(Self { root })
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn write(&self, path: &str, content: &str) -> Result<(), String> {
            let path = self.root.join(path);
            let parent = path
                .parent()
                .ok_or_else(|| "fixture path has no parent".to_owned())?;
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            fs::write(path, content).map_err(|error| error.to_string())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
