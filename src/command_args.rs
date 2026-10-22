//! Identify standalone command options without consuming their literal operands.

fn takes_value(command: &str, option: &str) -> bool {
    match command {
        "commit" | "pull" => matches!(option, "-m" | "--message"),
        "merge" => matches!(
            option,
            "-m" | "--message" | "--resolved" | "--expect-head" | "--expect-branch"
        ),
        "cherry-pick" | "revert" => matches!(
            option,
            "-m" | "--message" | "--mainline" | "--expect-head" | "--expect-branch" | "--empty"
        ),
        "rebase" => option == "--onto",
        "stash" => matches!(option, "-m" | "--message" | "--output"),
        "restore" => matches!(option, "--source" | "--file" | "--output"),
        "cat-file" => option == "--output",
        "switch" => option == "-c",
        "checkout" => matches!(option, "-b" | "--file"),
        "branch" => matches!(option, "-m" | "-d" | "-D" | "-u" | "--set-upstream-to"),
        "tag" => option == "-d",
        "push" => option == "--force-with-lease",
        "for-each-ref" => matches!(option, "--format" | "--sort" | "--count"),
        "describe" => matches!(option, "--abbrev" | "--match" | "--exclude"),
        "archive" => matches!(
            option,
            "-o" | "--output" | "--format" | "--prefix" | "--legacy-path"
        ),
        _ => false,
    }
}

/// Match the single-value options consumed by the hand-written dispatchers.
/// Their operands remain data even when equal to a help or transport flag.
enum Argument<'a> {
    Option(usize, &'a str),
    Separator(usize),
}

fn arguments(args: &[String]) -> impl Iterator<Item = Argument<'_>> {
    let command = args.first().map_or("", String::as_str);
    let config_value = args.len() == 4
        && args.first().is_some_and(|command| command == "config")
        && args[2] != "--unset";
    let mut operand = false;
    let mut options = true;
    args.iter()
        .enumerate()
        .skip(1)
        .filter_map(move |(index, arg)| {
            if operand {
                operand = false;
                return None;
            }
            if !options {
                return None;
            }
            if config_value && index == 3 {
                return None;
            }
            if arg == "--" {
                options = false;
                return Some(Argument::Separator(index));
            }
            if takes_value(command, arg) {
                operand = true;
            }
            Some(Argument::Option(index, arg.as_str()))
        })
}

fn option_arguments(args: &[String]) -> impl Iterator<Item = (usize, &str)> {
    arguments(args).filter_map(|arg| match arg {
        Argument::Option(index, value) => Some((index, value)),
        Argument::Separator(_) => None,
    })
}

/// A real delimiter, excluding an equal literal value of a preceding option.
pub fn separator_index(args: &[String]) -> Option<usize> {
    arguments(args).find_map(|arg| match arg {
        Argument::Separator(index) => Some(index),
        Argument::Option(_, _) => None,
    })
}

pub fn help_requested(args: &[String]) -> bool {
    option_arguments(args).any(|(_, arg)| matches!(arg, "-h" | "--help"))
}

/// Original argv positions, so removing one global flag never removes an equal
/// literal operand or changes the classification of the arguments that remain.
pub fn option_indices(args: &[String], option: &str) -> Vec<usize> {
    option_arguments(args)
        .filter_map(|(index, arg)| (arg == option).then_some(index))
        .collect()
}
