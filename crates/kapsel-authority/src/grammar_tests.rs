use super::*;

#[test]
fn identity_grammar_is_bounded_ascii() {
    for (value, valid) in [
        ("A._:-z0".into(), true),
        ("o".repeat(128), true),
        (String::new(), false),
        ("o".repeat(129), false),
        ("../outside".into(), false),
        ("space value".into(), false),
        ("é".into(), false),
        ("a\0b".into(), false),
    ] {
        assert_eq!(identity_is_valid(&value), valid, "{value:?}");
    }
}

#[test]
fn dns_label_grammar_covers_namespace_and_container() {
    for (value, valid) in [
        ("a".into(), true),
        ("0".into(), true),
        ("agent-api".into(), true),
        ("a".repeat(63), true),
        (String::new(), false),
        ("a".repeat(64), false),
        ("Uppercase".into(), false),
        ("-api".into(), false),
        ("api-".into(), false),
        ("agent_api".into(), false),
        ("agent.api".into(), false),
        ("é".into(), false),
    ] {
        assert_eq!(dns_label_is_valid(&value), valid, "{value:?}");
    }
}

#[test]
fn deployment_grammar_bounds_each_label_and_the_whole_name() {
    let maximum = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    for (value, valid) in [
        ("a".into(), true),
        ("agent-api.demo".into(), true),
        (maximum.clone(), true),
        (format!("{maximum}d"), false),
        (format!("{}.valid", "a".repeat(64)), false),
        (String::new(), false),
        (".api".into(), false),
        ("api.".into(), false),
        ("api..demo".into(), false),
        ("api.-demo".into(), false),
        ("agent_api".into(), false),
        ("Agent.api".into(), false),
        ("é.api".into(), false),
    ] {
        assert_eq!(dns_subdomain_is_valid(&value), valid, "{value:?}");
    }
}

#[test]
fn image_grammar_rejects_mutable_ambiguous_and_oversized_forms() {
    let digest = "0123456789abcdef".repeat(4);
    for (value, valid) in [
        (format!("registry.example/repo/image@sha256:{digest}"), true),
        (format!("a_b/c.d-e@sha256:{digest}"), true),
        (format!("0@sha256:{digest}"), true),
        (format!("{}@sha256:{digest}", "i".repeat(440)), true),
        (format!("{}@sha256:{digest}", "i".repeat(441)), false),
        (String::new(), false),
        ("registry.example/repo/image:tag".into(), false),
        (format!("sha256:{digest}"), false),
        (
            format!("registry.example/repo/image:tag@sha256:{digest}"),
            false,
        ),
        (
            format!("registry.example:5000/repo/image@sha256:{digest}"),
            false,
        ),
        (
            format!("Registry.example/repo/image@sha256:{digest}"),
            false,
        ),
        (format!("image@sha256:{}", digest.to_uppercase()), false),
        (format!("image@sha256:{}", "0".repeat(63)), false),
        (format!("image@sha256:{}", "0".repeat(65)), false),
        (format!("image@sha256:{}g", "0".repeat(63)), false),
        (format!("image@sha512:{digest}"), false),
        (format!("@sha256:{digest}"), false),
        (format!("/image@sha256:{digest}"), false),
        (format!("image/@sha256:{digest}"), false),
        (format!("repo//image@sha256:{digest}"), false),
        (format!("repo/-image@sha256:{digest}"), false),
        (format!("repo/image_@sha256:{digest}"), false),
        (format!("image@extra@sha256:{digest}"), false),
        (format!("image@sha256:{digest}@sha256:{digest}"), false),
        (format!("é/image@sha256:{digest}"), false),
    ] {
        assert_eq!(immutable_image_is_valid(&value), valid, "{value:?}");
    }
}
