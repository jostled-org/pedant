//! The `go.mod` line grammar: comments, quoted tokens, and factored blocks.
//!
//! `go.mod` is line-oriented. A verb either carries its arguments on one line or
//! opens a parenthesized block whose every line carries one argument list for
//! that same verb. Both forms reduce to the same record here, so every reader
//! above works with verbs and arguments and none of them re-implements the
//! block state.

/// One directive: its verb, its arguments, and the line it was written on.
pub(super) struct GoDirective {
    pub(super) verb: Box<str>,
    pub(super) arguments: Box<[Box<str>]>,
    pub(super) line: u32,
}

/// Why a manifest does not match the `go.mod` line grammar.
pub(super) struct GoDirectiveError {
    pub(super) line: u32,
    pub(super) message: Box<str>,
}

/// The token that separates a replacement's old side from its new side.
pub(super) const ARROW: &str = "=>";

/// Read every directive one manifest states.
pub(super) fn parse(text: &str) -> Result<Box<[GoDirective]>, GoDirectiveError> {
    let mut directives: Vec<GoDirective> = Vec::new();
    let mut block: Option<(Box<str>, u32)> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = line_number(index);
        let tokens = tokenize(raw, line)?;
        block = fold_line(&mut directives, block, (tokens, line))?;
    }
    match block {
        Some((verb, line)) => Err(GoDirectiveError {
            line,
            message: format!("the {verb} block is never closed").into_boxed_str(),
        }),
        None => Ok(directives.into_boxed_slice()),
    }
}

/// The block state one line's tokens leave behind: the verb still open, and the
/// line that opened it.
type BlockState = Option<(Box<str>, u32)>;

/// Apply one tokenized line to the directive list, returning the block state
/// that survives it.
///
/// The tokens arrive owned and are moved through: `tokenize` allocates each one
/// exactly once, and every reader above takes the same allocation rather than a
/// copy of it.
fn fold_line(
    directives: &mut Vec<GoDirective>,
    block: BlockState,
    line: (Box<[Box<str>]>, u32),
) -> Result<BlockState, GoDirectiveError> {
    match block {
        Some(open) => Ok(fold_inside_block(directives, open, line)),
        None => fold_at_top_level(directives, line),
    }
}

/// One line of a factored block: its tokens are arguments of the open verb, and
/// a trailing `)` closes it.
fn fold_inside_block(
    directives: &mut Vec<GoDirective>,
    open: (Box<str>, u32),
    line: (Box<[Box<str>]>, u32),
) -> BlockState {
    let (verb, opened) = open;
    let (tokens, number) = line;
    let (arguments, closed) = split_close(tokens.into_vec());
    record(directives, (&verb, arguments), number);
    match closed {
        true => None,
        false => Some((verb, opened)),
    }
}

/// One line outside any block: an empty line, a block opening, or a whole
/// directive.
fn fold_at_top_level(
    directives: &mut Vec<GoDirective>,
    line: (Box<[Box<str>]>, u32),
) -> Result<BlockState, GoDirectiveError> {
    let (tokens, number) = line;
    let mut tokens = tokens.into_vec();
    let Some(verb) = held_verb(&mut tokens, number)? else {
        return Ok(None);
    };
    let opens = first_is(&tokens, "(");
    let body = tokens.split_off(usize::from(opens));
    let (arguments, closed) = split_close(body);
    check_close(opens, closed, number)?;
    record(directives, (&verb, arguments), number);
    Ok(match opens && !closed {
        true => Some((verb, number)),
        false => None,
    })
}

/// The verb one top-level line opens with, moved out of its own token list.
///
/// A line stating nothing opens no directive. A line opening with `)` closes a
/// block that was never opened.
fn held_verb(tokens: &mut Vec<Box<str>>, line: u32) -> Result<Option<Box<str>>, GoDirectiveError> {
    let Some(verb) = pop_first(tokens) else {
        return Ok(None);
    };
    match &*verb == ")" {
        true => Err(closed_unopened(line)),
        false => Ok(Some(verb)),
    }
}

/// The first token of a line, moved out of it.
fn pop_first(tokens: &mut Vec<Box<str>>) -> Option<Box<str>> {
    match tokens.is_empty() {
        true => None,
        false => Some(tokens.remove(0)),
    }
}

/// A top-level line's `)` closes only the block that same line opened.
///
/// Without this, `split_close` strips the token either way and the malformed
/// `require example.com/x v1.0.0 )` is admitted as a well-formed requirement.
fn check_close(opens: bool, closed: bool, line: u32) -> Result<(), GoDirectiveError> {
    match closed && !opens {
        false => Ok(()),
        true => Err(closed_unopened(line)),
    }
}

/// The one refusal a stray `)` earns.
fn closed_unopened(line: u32) -> GoDirectiveError {
    GoDirectiveError {
        line,
        message: Box::from("a block is closed without being opened"),
    }
}

/// A line's arguments, and whether the line ended with a `)`.
fn split_close(tokens: Vec<Box<str>>) -> (Vec<Box<str>>, bool) {
    let mut arguments = tokens;
    match arguments.last().is_some_and(|last| &**last == ")") {
        false => (arguments, false),
        true => {
            arguments.pop();
            (arguments, true)
        }
    }
}

/// Whether a line's remaining tokens open with `token`.
fn first_is(tokens: &[Box<str>], token: &str) -> bool {
    tokens.first().is_some_and(|held| &**held == token)
}

/// Record one directive, unless the line stated no arguments for it.
fn record(directives: &mut Vec<GoDirective>, entry: (&str, Vec<Box<str>>), line: u32) {
    let (verb, arguments) = entry;
    match arguments.is_empty() {
        true => (),
        false => directives.push(GoDirective {
            verb: verb.into(),
            arguments: arguments.into_boxed_slice(),
            line,
        }),
    }
}

/// The tokens one line states, with its comment removed.
fn tokenize(raw: &str, line: u32) -> Result<Box<[Box<str>]>, GoDirectiveError> {
    let mut tokens: Vec<Box<str>> = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut characters = raw.chars().peekable();
    while let Some(character) = characters.next() {
        match (quoted, character) {
            (true, '"') => quoted = false,
            (true, _) => current.push(character),
            (false, '"') => quoted = true,
            (false, '/') if characters.peek() == Some(&'/') => break,
            (false, _) if character.is_whitespace() => flush(&mut tokens, &mut current),
            (false, _) => current.push(character),
        }
    }
    match quoted {
        true => Err(GoDirectiveError {
            line,
            message: Box::from("the line ends inside a quoted token"),
        }),
        false => {
            flush(&mut tokens, &mut current);
            Ok(tokens.into_boxed_slice())
        }
    }
}

/// Close the token being read, if one is open.
fn flush(tokens: &mut Vec<Box<str>>, current: &mut String) {
    match current.is_empty() {
        true => (),
        false => tokens.push(std::mem::take(current).into_boxed_str()),
    }
}

/// The one-based line number of a zero-based enumeration index.
fn line_number(index: usize) -> u32 {
    u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
}
