// In place of @xterm/addon-ligatures in the workbench build. That addon reads font files through Node's own
// modules, which a browser does not have, so it cannot be bundled for a page. The workbench loads it only when
// `terminal.integrated.fontLigatures.enabled` is turned on; here that setting then does nothing.
export class LigaturesAddon {
  activate() {}
  dispose() {}
}
