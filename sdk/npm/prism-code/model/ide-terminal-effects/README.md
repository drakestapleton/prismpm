# Terminal outside effects, version 1

2026-11-20. Model: `src/App.lex.tex`, written by `tools/gen_effects.py`. A rule table, proved by `../ide-prove-rule-app.mjs` with this checkout's prism-code. Nothing is sent anywhere.

It is a specification. No terminal is built yet (`docs/proposals/prism-ide-phase-2.md`, phase 2f).

## What it decides

What the Prism IDE's embedded terminal does when output or input asks for something outside its grid of characters: `ignore`, `apply` or `ask`.

Terminal output is untrusted. A file printed to the screen can hold control sequences, and xterm.js's own security guide says to treat titles, links and parser hooks that way. Each such request is one of these:

| Effect | Sequence | In xterm.js 6.0.0 |
|---|---|---|
| title | OSC 0, 2 | core; reported by `onTitleChange` |
| link | OSC 8, or an address the web-links addon finds | core; with no `linkHandler` the browser's own confirm box is shown |
| clipboardwrite, clipboardread | OSC 52 set and query | not in the core's list; the clipboard addon handles it |
| notify | OSC 9, OSC 777 | not in the core's list |
| transfer | OSC 1337 `File=`, sixel, kitty graphics | the image addon only |
| window | CSI `t` | every option is off by default |
| paste | text from the clipboard typed in | `paste()` |
| other | anything else that would act outside the grid | |

A request is four words, in order:

| Field | Values | Meaning |
|---|---|---|
| effect | the nine above | what is asked for |
| gesture | no, yes | the user's own click or key press asked for it, in this tab, just now |
| scheme | none, other, https | for a link, what its address starts with |
| multiline | no, yes | for a paste, whether the text holds a line break |

Rules, first match decides:

1. a title → apply
2. a link, clicked, to an `https` address → ask, showing the whole address
3. a paste the user made, holding a line break → ask, showing the text
4. a paste the user made, on one line → apply
5. otherwise → ignore

## Proved

Lean's kernel accepted all 17, for every request.

1. to 6. An unlisted effect, a clipboard write, a clipboard read, a notification, a transfer and a window operation are each always ignored.
7. A link is never applied: none opens without the question.
8. A link nobody clicked is always ignored.
9. and 10. A link with no address scheme, or any scheme other than `https`, is always ignored.
11. A clicked `https` link always asks.
12. A paste the user did not make is always ignored.
13. A paste holding a line break is never applied without the question.
14. and 15. A paste the user made asks when it holds a line break and is applied when it does not.
16. With no gesture, nothing ever asks: output alone cannot raise a question.
17. A title is always applied.

Model identity: `sha256:43a0a53ee6648a706f442d8058b1a9ef1b1d110a1c924056032307f2666c73f1`.
Built app: `sha256:a949a269b45761419a753184085d6b3bb49a7ff02aa75e4d8ec1b49db66d5833`.
These names are SHA-256 because that is what prism-code emits today.

## Tested, not proved

17 of 17 acceptance vectors pass through the built judge.
A planted defect (open a clicked link without asking) is refused in CI, and the step checks that the kernel names guarantee 7 and the request `link yes https no`.

## Not covered

That every such sequence reaches this table is the page's job and is unproved. In the edit page (`ide/edit/terminal/effects.mjs`) a handler is registered for each sequence through xterm.js's parser hooks, with a `linkHandler`, and the clipboard and image addons are not loaded at all. One does not reach the table: xterm.js 6.0.0 drops every window operation itself while its `windowOptions` are off, and they are. xterm.js's parser is not modelled.
"Apply" for a title means setting it as plain text, cut to a fixed length. That is page code.
Whether a gesture was the user's is the browser's word (`isTrusted`, user activation), read by the page.
The table does not judge what stays inside the grid: colours, cursor moves, the alternate screen, mouse reporting.
A link the user confirms is opened by the browser in a new tab. Where it leads is not judged beyond its scheme.
The sequence numbers in the table above were read from xterm.js's documentation on 2026-11-20. Where OSC 52 is handled in 6.0.0 was not confirmed from the source.
`lexlean fmt` was not run on this model.
