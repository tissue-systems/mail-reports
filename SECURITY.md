# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately
through [GitHub's security advisory form](https://github.com/tissue-systems/mail-reports/security/advisories/new)
or by email to [security@tissue.systems](mailto:security@tissue.systems),
with what you found and the steps to reproduce it. A message or a report file
that shows the problem is the most useful thing you can send.

We'll write back within three working days and credit you in the release
notes unless you'd rather we didn't. Please give us 90 days, or until a fix
ships if that's sooner, before you publish.

## Supported versions

mail-reports is pre-1.0. Fixes go into the latest 0.x release only.

## What's in scope

A report address is published in DNS and anyone can mail it, so every input
is hostile. These are vulnerabilities:

- a message or report file that makes a parser panic
- one that gets past a cap in `Limits`, or makes a parser use memory or time
  far out of proportion to its size while staying inside them
- a parse that runs well past its deadline
- body text of a reported message kept in a failure report, which holds
  headers only
- text in an `InvalidReport` that isn't one line of printable ASCII

Things the README lists under "What it doesn't do" aren't vulnerabilities in
mail-reports: it doesn't authenticate the report message, so a forged report
that parses is the caller's to refuse. The size of the raw message is the
caller's to limit too, before it gets here. Bugs in mail-parser, quick-xml,
flate2 or zip themselves go upstream. If you're not sure, send it anyway.
