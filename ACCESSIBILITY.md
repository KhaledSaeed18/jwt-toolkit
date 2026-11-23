# Accessibility

jwt-toolkit should be usable by everyone who works in a terminal, including people who use a screen reader or a braille display, magnification, high-contrast or custom color schemes, or who can't tell some colors apart. This statement describes what it does for that today, where it falls short, and how to report a barrier.

## Commitment

- Every verdict is in words. Color only repeats what the text already says.
- Every result that matters for a decision is available as JSON, so you can read it with the tools that work best for you.
- Accessibility problems are bugs, and they are handled like any other bug.

## Terminal output

**Words carry the meaning.** `verify` labels every check `PASS`, `FAIL` or `WARN` and ends with `VALID` or `INVALID`. `audit` labels every finding with its severity (`CRITICAL`, `WARN`, `INFO`, `PASS`) and states the grade as a letter and a word (`SECURE`, `WEAK`, `INSECURE`). `crack` says whether it found the secret. The exit code says the same thing: `0` passed, `1` found a problem, `2` the input could not be used; the README lists them under [Exit codes](https://github.com/KhaledSaeed18/jwt-toolkit#scripting-and-ci).

**Color is optional and off when it can't help.** Colors and text styles are used only when output is an interactive terminal. They are off when output is piped or written to a file, when `NO_COLOR` is set, when `TERM=dumb`, or with `--no-color`; with `NO_COLOR` or `--no-color` the output contains no escape codes at all, not even bold or dim. The colors are the terminal's own standard ones, so your terminal theme decides how they look.

**Movement is limited and can be turned off.** A bare `jwt-toolkit` shows an animated banner only in an interactive terminal; it is static or absent in a pipe, in CI, under `NO_COLOR` or `TERM=dumb`, and `--no-banner` or `--quiet` removes it. `crack` and `download-wordlists` draw a progress line on stderr that disappears when the work is done; `--quiet` hides it.

**No hidden characters from tokens.** Header and claim values come from the token, which may be hostile. They are escaped before they are printed, so control characters, terminal escape sequences and bidirectional overrides in a token can't reach your terminal or your screen reader as noise or as commands. Errors and progress go to stderr; results go to stdout.

## Machine-readable output

`decode`, `audit`, `verify`, `diff`, `forge` and `crack` accept `--json`, which gives the full result as a JSON document with a stable shape. `sign` prints only the token, and `generate-secret --raw` prints only the secret, so both read cleanly with any tool.

## Documentation

The README and the other Markdown files use real headings, lists and tables, so they can be navigated by structure. The README header image has a text alternative. Command examples and sample output are text in code blocks.

## Known limitations

- **Drawing characters.** Panels and tables are drawn with box-drawing characters (`╭─╮`, `│`). Some screen readers read them aloud as symbols. `--json` gives the same data without them.
- **Banner art.** The banner of a bare `jwt-toolkit` is large ASCII lettering that a screen reader reads as symbols. Use `--no-banner`, or run a command directly; commands never print the banner.
- **Aligned columns.** Tables pad columns with spaces to line them up. A screen reader reads the padding as a pause, and in a narrow terminal long values may wrap.
- **Checksum mark.** `download-wordlists` marks a matching checksum with `✓` rather than a word; the exit code (`0`) says the same.
- **Fixed color choice.** The terminal colors can't be changed. Set `NO_COLOR=1` to turn them off.
- **No formal audit.** The output has not been reviewed with every screen reader and terminal combination.

## Reporting a barrier

If something in jwt-toolkit or its documentation is hard or impossible to use with the way you work, please [open an accessibility issue](https://github.com/KhaledSaeed18/jwt-toolkit/issues/new?template=accessibility.yml). Say what you were trying to do, what you use (for example a screen reader and its version, a terminal, a color scheme) and what got in the way. Never paste a real token or secret; a redacted header and claims are enough. If you'd rather not report it in public, email [khaled18saeed@gmail.com](mailto:khaled18saeed@gmail.com).

Barriers are triaged like bugs. A fix that changes output may change the wording and layout of human-readable output in a minor release; `--json` output only gains fields.

This statement was last reviewed for jwt-toolkit 1.4.0.
