//! Root-relative selectors over actual portable Wasm tree paths. Matching never
//! traverses the filesystem; callers supply the admitted candidate set first.
use globset::{GlobBuilder, GlobMatcher};
use std::collections::BTreeSet;

pub struct Pathspec {
    patterns: Vec<Pattern>,
}
struct Pattern {
    original: String,
    expression: String,
    matcher: Option<GlobMatcher>,
    icase: bool,
    directory: bool,
    exclude: bool,
}

impl Pattern {
    fn parse(original: &str) -> Result<Self, String> {
        if original.is_empty() || original.len() > 8192 || original.chars().any(char::is_control) {
            return Err("pathspec must contain 1-8192 bytes without control characters".into());
        }
        let (mut literal, mut glob, mut icase, mut exclude) = (false, false, false, false);
        let mut expression = original;
        if let Some(rest) = expression.strip_prefix(":(") {
            let (magic, pattern) = rest.split_once(')').ok_or("unterminated pathspec magic")?;
            let mut seen = BTreeSet::new();
            for word in magic.split(',').filter(|word| !word.is_empty()) {
                if !seen.insert(word) {
                    return Err(format!("duplicate pathspec magic: {word}"));
                }
                match word {
                    "top" => {}
                    "literal" => literal = true,
                    "glob" => glob = true,
                    "icase" => icase = true,
                    "exclude" => exclude = true,
                    _ => return Err(format!("unsupported native pathspec magic: {word}")),
                }
            }
            expression = pattern;
        } else if let Some(rest) = expression.strip_prefix(':') {
            let end = rest.bytes().take_while(|b| b"/!^".contains(b)).count();
            exclude = rest[..end].contains(['!', '^']);
            expression = rest[end..].strip_prefix(':').unwrap_or(&rest[end..]);
        }
        if literal && glob {
            return Err("literal and glob pathspec magic are mutually exclusive".into());
        }
        expression = expression.strip_prefix("./").unwrap_or(expression);
        let directory = expression.ends_with('/');
        expression = expression.strip_suffix('/').unwrap_or(expression);
        if matches!(expression, "." | "") {
            return Ok(Self {
                original: original.into(),
                expression: String::new(),
                matcher: None,
                icase,
                directory: false,
                exclude,
            });
        }
        // Escapes belong to the pattern, never to a repository path. Reject
        // traversal/metadata even when there are no matching candidates.
        if expression.starts_with('/')
            || expression.contains(':')
            || expression
                .split('/')
                .any(|part| matches!(part, "" | "." | "..") || part.eq_ignore_ascii_case(".uwgit"))
            || (literal && expression.contains('\\'))
        {
            return Err(format!("invalid root-relative pathspec: {original:?}"));
        }
        if glob {
            for part in expression.split('/') {
                if part.contains("**") && part != "**" {
                    return Err("glob ** must occupy a complete path component".into());
                }
            }
        }
        let matcher = if literal {
            None
        } else {
            let mut escaped = String::new();
            let mut chars = expression.chars();
            while let Some(character) = chars.next() {
                if character == '\\' {
                    escaped.push(character);
                    escaped.push(chars.next().ok_or("pathspec ends with an escape")?);
                } else {
                    if matches!(character, '{' | '}') {
                        escaped.push('\\');
                    }
                    escaped.push(character);
                }
            }
            Some(
                GlobBuilder::new(&escaped)
                    .literal_separator(glob)
                    .case_insensitive(icase)
                    .backslash_escape(true)
                    .build()
                    .map_err(|error| format!("invalid pathspec {original:?}: {error}"))?
                    .compile_matcher(),
            )
        };
        Ok(Self {
            original: original.into(),
            expression: expression.into(),
            matcher,
            icase,
            directory,
            exclude,
        })
    }
    fn exact(&self, value: &str) -> bool {
        if self.expression.is_empty() {
            return true;
        }
        if let Some(matcher) = &self.matcher {
            matcher.is_match(value)
        } else if self.icase {
            self.expression.eq_ignore_ascii_case(value)
        } else {
            self.expression == value
        }
    }
    fn matches(&self, path: &str) -> bool {
        if !self.directory && self.exact(path) {
            return true;
        }
        path.match_indices('/')
            .any(|(offset, _)| self.exact(&path[..offset]))
    }
}

impl Pathspec {
    pub fn new(selectors: &[String]) -> Result<Self, String> {
        if selectors.len() > 4096 {
            return Err("at most 4096 pathspecs are supported".into());
        }
        if selectors.len() > 1 && selectors.iter().any(|value| value == ":") {
            return Err("the no-pathspec ':' form must be used alone".into());
        }
        Ok(Self {
            patterns: selectors
                .iter()
                .map(|value| Pattern::parse(value))
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn matches(&self, path: &str) -> bool {
        (self.patterns.iter().all(|pattern| pattern.exclude)
            || self
                .patterns
                .iter()
                .any(|pattern| !pattern.exclude && pattern.matches(path)))
            && !self
                .patterns
                .iter()
                .any(|pattern| pattern.exclude && pattern.matches(path))
    }
    /// Existing mutating command admission remains strict: every positive
    /// selector must match before exclusions are applied. Exclusions may match
    /// nothing. A completely excluded result is an admitted empty selection.
    pub fn select(&self, candidates: &BTreeSet<String>) -> Result<BTreeSet<String>, String> {
        for pattern in &self.patterns {
            if !pattern.exclude && !candidates.iter().any(|path| pattern.matches(path)) {
                return Err(format!(
                    "path selector did not match any tracked or source path: {:?}",
                    pattern.original
                ));
            }
        }
        Ok(candidates
            .iter()
            .filter(|path| self.matches(path))
            .cloned()
            .collect())
    }
}

pub fn select(
    candidates: &BTreeSet<String>,
    selectors: &[String],
) -> Result<BTreeSet<String>, String> {
    Pathspec::new(selectors)?.select(candidates)
}
