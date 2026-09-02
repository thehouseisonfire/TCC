use anyhow::{Context, Result, bail};
use percent_encoding::percent_decode_str;
use pulldown_cmark::{Event, Parser, Tag, TagEnd};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> Result<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("tools/check-docs should live at <repo>/tools/check-docs")
}

fn tracked_markdown(root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", "*.md"])
        .current_dir(root)
        .output()
        .context("failed to list tracked Markdown files")?;
    if !output.status.success() {
        bail!("git ls-files failed");
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| root.join(String::from_utf8_lossy(path).as_ref()))
        .collect())
}

fn github_slug(heading: &str) -> String {
    let mut slug = String::new();
    for character in heading.trim().to_lowercase().chars() {
        if character.is_alphanumeric() || character == '-' || character == '_' {
            slug.push(character);
        } else if character.is_whitespace() {
            slug.push('-');
        }
    }
    slug
}

fn add_anchor(
    anchors: &mut HashSet<String>,
    duplicates: &mut HashMap<String, usize>,
    heading: &str,
) {
    let base = github_slug(heading);
    let count = duplicates.entry(base.clone()).or_default();
    let rendered = if *count == 0 {
        base
    } else {
        format!("{base}-{count}")
    };
    *count += 1;
    anchors.insert(rendered);
}

fn anchors(markdown: &str) -> Result<HashSet<String>> {
    let explicit = Regex::new(r#"<a\s+(?:id|name)=["']([^"']+)["']"#)?;
    let mut anchors = HashSet::new();
    let mut duplicates: HashMap<String, usize> = HashMap::new();
    let mut heading_text: Option<String> = None;

    for event in Parser::new(markdown) {
        match event {
            Event::Start(Tag::Heading { .. }) => heading_text = Some(String::new()),
            Event::End(TagEnd::Heading(_)) => {
                let Some(text) = heading_text.take() else {
                    continue;
                };
                add_anchor(&mut anchors, &mut duplicates, &text);
            }
            Event::Text(text)
            | Event::Code(text)
            | Event::InlineMath(text)
            | Event::DisplayMath(text) => {
                if let Some(heading) = &mut heading_text {
                    heading.push_str(&text);
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if let Some(heading) = &mut heading_text {
                    heading.push(' ');
                }
            }
            Event::Html(html) | Event::InlineHtml(html) => {
                for capture in explicit.captures_iter(&html) {
                    anchors.insert(capture[1].to_owned());
                }
            }
            _ => {}
        }
    }
    Ok(anchors)
}

fn is_external(destination: &str) -> bool {
    if destination.starts_with("//") {
        return true;
    }

    let Some((scheme, _)) = destination.split_once(':') else {
        return false;
    };
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn line_number_at(content: &str, offset: usize) -> usize {
    content[..offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn check_destination(
    source: &Path,
    line_number: usize,
    raw_destination: &str,
    known_anchors: &HashMap<PathBuf, HashSet<String>>,
    failures: &mut Vec<String>,
) {
    let destination = raw_destination;
    if destination.is_empty() || is_external(destination) {
        return;
    }

    let (path_and_query, fragment) = destination
        .split_once('#')
        .map_or((destination, None), |(path, anchor)| (path, Some(anchor)));
    let path_part = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _)| path);
    let path_part = percent_decode_str(path_part).decode_utf8_lossy();
    let fragment = fragment.map(|value| percent_decode_str(value).decode_utf8_lossy());
    let target = if path_part.is_empty() {
        source.to_path_buf()
    } else {
        source
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path_part.as_ref())
    };

    if !target.exists() {
        failures.push(format!(
            "{}:{line_number}: missing local target `{destination}`",
            source.display()
        ));
        return;
    }

    if let Some(fragment) = fragment
        && target.extension().and_then(|extension| extension.to_str()) == Some("md")
    {
        let canonical = target.canonicalize().unwrap_or(target);
        if !known_anchors
            .get(&canonical)
            .is_some_and(|anchors| anchors.contains(fragment.as_ref()))
        {
            failures.push(format!(
                "{}:{line_number}: missing Markdown anchor `#{fragment}` in `{}`",
                source.display(),
                canonical.display()
            ));
        }
    }
}

fn check_markdown_files(files: &[PathBuf]) -> Result<Vec<String>> {
    let html_tag = Regex::new(r#"(?is)<[a-z](?:[^>"']|"[^"]*"|'[^']*')*>"#)?;
    let html_link =
        Regex::new(r#"(?ix)(?:^|\s)(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#)?;
    let mut known_anchors = HashMap::new();
    let mut contents = HashMap::new();

    for file in files {
        let content = fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let canonical = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
        known_anchors.insert(canonical.clone(), anchors(&content)?);
        contents.insert(canonical, content);
    }

    let mut failures = Vec::new();
    for (file, content) in contents {
        if content.contains("cite") || content.contains("entity") {
            failures.push(format!(
                "{}: contains unresolved internal citation markers",
                file.display()
            ));
        }

        let parser = Parser::new(&content);
        for (_, definition) in parser.reference_definitions().iter() {
            check_destination(
                &file,
                line_number_at(&content, definition.span.start),
                &definition.dest,
                &known_anchors,
                &mut failures,
            );
        }

        for (event, range) in parser.into_offset_iter() {
            match event {
                Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                    check_destination(
                        &file,
                        line_number_at(&content, range.start),
                        &dest_url,
                        &known_anchors,
                        &mut failures,
                    );
                }
                Event::Html(html) | Event::InlineHtml(html) => {
                    for tag in html_tag.find_iter(&html) {
                        for capture in html_link.captures_iter(tag.as_str()) {
                            let Some(destination) =
                                capture.get(1).or(capture.get(2)).or(capture.get(3))
                            else {
                                continue;
                            };
                            check_destination(
                                &file,
                                line_number_at(&content, range.start),
                                destination.as_str(),
                                &known_anchors,
                                &mut failures,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(failures)
}

fn run() -> Result<()> {
    let root = repo_root()?;
    let files = tracked_markdown(&root)?;
    let failures = check_markdown_files(&files)?;
    if !failures.is_empty() {
        for failure in failures {
            eprintln!("{failure}");
        }
        bail!("documentation audit failed");
    }
    println!(
        "Documentation audit passed for {} tracked Markdown files.",
        files.len()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Event, Parser, Tag, anchors, check_destination, check_markdown_files, github_slug,
        is_external,
    };
    use std::collections::HashMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn github_slug_removes_heading_punctuation() {
        assert_eq!(github_slug("3.1.2.1 Protocol Name"), "3121-protocol-name");
    }

    #[test]
    fn recognizes_uri_schemes_and_protocol_relative_urls() {
        for destination in [
            "https://example.com",
            "ftp://example.com/report.md",
            "tel:+15551234567",
            "ssh://example.com/repository",
            "git+ssh://example.com/repository",
            "CUSTOM+SCHEME:value",
            "//example.com/report.md",
        ] {
            assert!(is_external(destination), "{destination}");
        }

        for destination in [
            "report.md",
            "results/run_(1).md",
            "./directory:name/report.md",
            "#local-anchor",
        ] {
            assert!(!is_external(destination), "{destination}");
        }
    }

    #[test]
    fn markdown_parser_preserves_balanced_parentheses_in_destinations() {
        for markdown in [
            "[report](results/run_(1).md)",
            r"[report](results/run_\(1\).md)",
        ] {
            let destination = Parser::new(markdown).find_map(|event| match event {
                Event::Start(Tag::Link { dest_url, .. }) => Some(dest_url.into_string()),
                _ => None,
            });

            assert_eq!(destination.as_deref(), Some("results/run_(1).md"));
        }
    }

    #[test]
    fn local_link_destinations_can_contain_spaces() {
        let markdown = "[report](<results/my run.md>)";
        let destination = Parser::new(markdown)
            .find_map(|event| match event {
                Event::Start(Tag::Link { dest_url, .. }) => Some(dest_url.into_string()),
                _ => None,
            })
            .expect("link destination should parse");
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("repo-check-docs-{}-{unique}", std::process::id()));
        let results = directory.join("results");
        fs::create_dir_all(&results).expect("temporary results directory should be created");
        fs::write(results.join("my run.md"), "# Report\n")
            .expect("temporary report should be written");

        let mut failures = Vec::new();
        check_destination(
            &directory.join("source.md"),
            1,
            &destination,
            &HashMap::new(),
            &mut failures,
        );
        fs::remove_dir_all(&directory).expect("temporary directory should be removed");

        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn anchors_use_rendered_heading_text_for_atx_and_setext_headings() {
        let found = anchors(concat!(
            "Rendered [link](target.md) &amp; `code`\n",
            "=========================================\n",
            "\n",
            "# Rendered link &amp; `code`\n",
        ))
        .expect("anchors should parse");

        assert!(found.contains("rendered-link--code"));
        assert!(found.contains("rendered-link--code-1"));
        assert!(!found.contains("rendered-linktargetmd-amp-code"));
    }

    #[test]
    fn local_urls_decode_paths_and_ignore_queries() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "repo-check-docs-url-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary directory should be created");
        let source = directory.join("source.md");
        let target = directory.join("my run.md");
        fs::write(
            &source,
            concat!(
                "[encoded path](my%20run.md)\n",
                "[query and fragment](my%20run.md?plain=1#sec%74ion)\n",
            ),
        )
        .expect("temporary source should be written");
        fs::write(&target, "# Section\n").expect("temporary target should be written");

        let failures = check_markdown_files(&[source, target]).expect("Markdown should be checked");
        fs::remove_dir_all(&directory).expect("temporary directory should be removed");

        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn html_link_attributes_support_standard_syntax() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "repo-check-docs-html-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary directory should be created");
        let source = directory.join("source.md");
        fs::write(
            &source,
            concat!(
                "<IMG SRC=\"missing-one.png\">\n",
                "<a href = 'missing-two.md'>missing</a>\n",
                "<img src=missing-three.png>\n",
                "<div data-src=not-a-link.png></div>\n",
            ),
        )
        .expect("temporary source should be written");

        let failures = check_markdown_files(&[source]).expect("Markdown should be checked");
        fs::remove_dir_all(&directory).expect("temporary directory should be removed");

        assert_eq!(failures.len(), 3, "{failures:?}");
        for destination in ["missing-one.png", "missing-two.md", "missing-three.png"] {
            assert!(
                failures.iter().any(|failure| failure.contains(destination)),
                "{destination}: {failures:?}"
            );
        }
    }
}
