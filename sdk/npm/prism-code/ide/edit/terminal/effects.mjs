// What terminal output and input may do outside the grid of characters. Each request is put to the proved
// effects table (model/ide-terminal-effects) and its answer obeyed: ignore, apply or ask.
//
// Terminal output is untrusted: a printed file can hold any sequence. So every sequence that would act outside the
// grid has a handler here that takes it away from xterm.js, and the clipboard and image addons are never loaded.
// That each sequence reaches the table is tested (in the page), not proved.

/** What a link's address starts with, as the table names it. */
export const schemeOf = (uri) => (/^https:\/\//i.test(uri) ? 'https' : /^[a-z][a-z0-9+.-]*:/i.test(uri) ? 'other' : 'none');

const TITLE_MAX = 80;
/** A title as plain text: no control bytes, cut to a fixed length. */
export const cleanTitle = (text) => text.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').slice(0, TITLE_MAX);

/**
 * The effects of one terminal. `judge` is session.mjs's; `ui` is the page: setTitle(text), confirm(text) resolving
 * yes or no, open(address). `seen` records every request and its answer.
 */
export function createEffects({ judge, ui }) {
  const seen = [];
  const decide = (effect, { gesture = false, scheme = 'none', multiline = false } = {}) => {
    let answer = 'ignore';
    try { answer = judge('effects', { effect, gesture: gesture ? 'yes' : 'no', scheme, multiline: multiline ? 'yes' : 'no' }); } catch { /* an unknown word is ignored */ }
    seen.push({ effect, gesture, scheme, multiline, answer });
    return answer;
  };

  /** A link was activated: `event` is the browser's, and only its own word says the user clicked. */
  async function link(event, uri) {
    const answer = decide('link', { gesture: event?.isTrusted === true, scheme: schemeOf(uri) });
    if (answer === 'ask' && await ui.confirm('Open this address in a new tab?\n\n' + uri)) ui.open(uri);
  }

  /** Text arrived from the clipboard. Resolves the lines to enter, or none. */
  async function paste(event, text) {
    const multiline = /[\r\n]/.test(text);
    const answer = decide('paste', { gesture: event?.isTrusted === true, multiline });
    const lines = text.split(/\r\n|\r|\n/).filter((l) => l.trim());
    if (answer === 'apply') return { text };
    if (answer === 'ask' && await ui.confirm(`Run these ${lines.length} pasted lines?\n\n` + lines.join('\n').slice(0, 600))) return { lines };
    return null;
  }

  /** Take every outside-acting sequence away from the terminal. `term` is an xterm.js Terminal. */
  function install(term) {
    term.onTitleChange((text) => { if (decide('title') === 'apply') ui.setTitle(cleanTitle(text)); });
    // OSC 52: `c;?` asks for the clipboard, anything else sets it.
    term.parser.registerOscHandler(52, (data) => { decide(/;\?$/.test(data) ? 'clipboardread' : 'clipboardwrite'); return true; });
    for (const id of [9, 777]) term.parser.registerOscHandler(id, () => { decide('notify'); return true; });
    term.parser.registerOscHandler(1337, () => { decide('transfer'); return true; });
    // Sixel: DCS ... q.
    term.parser.registerDcsHandler({ final: 'q' }, () => { decide('transfer'); return true; });
    // Window operations: CSI ... t. xterm.js itself drops every one while its windowOptions are off, which they are
    // here, and hands a handler only those that are on. So this is reached only if an option is ever turned on.
    term.parser.registerCsiHandler({ final: 't' }, () => { decide('window'); return true; });
  }

  return { seen, decide, link, paste, install, linkHandler: { activate: link, allowNonHttpProtocols: false } };
}
