/** Markdown + KaTeX rendering; protect code before recognizing math. */
window.ICS = window.ICS || {};
var _FORMULA_PLACEHOLDER_PREFIX = "";
var _FORMULA_PLACEHOLDER_SUFFIX = "";
function _stashFormulas(mdText) {
  var formulas = [];
  function stash(value) {
    var key = _FORMULA_PLACEHOLDER_PREFIX + formulas.length + _FORMULA_PLACEHOLDER_SUFFIX;
    formulas.push(value);
    return key;
  }
  var text = mdText.replace(
    /(^ {0,3}(`{3,}|~{3,})[^\n]*\n[\s\S]*?^ {0,3}\2[ \t]*(?=\n|$))|(`+)([^\n]*?)\3|(\\\[[\s\S]*?\\\])|(\\\([^\n]*?\\\))|\$\$([\s\S]*?)\$\$|(?<![\\$])\$(?!\$)([^\n$]+?)\$(?!\$)/gm,
    function (match, fence, marker, ticks, code, display, inline, dollars, single) {
      if (fence || ticks) return match;
      if (display || inline) return stash(match);
      return stash(dollars !== undefined ? "\\[" + dollars + "\\]" : "\\(" + single + "\\)");
    }
  );
  return { text: text, formulas: formulas };
}
function _restoreFormulas(html, formulas) {
  for (var i = 0; i < formulas.length; i++) {
    // Math is text: preserve comparisons through HTML parsing and sanitization.
    var escaped = formulas[i].replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    html = html.split(_FORMULA_PLACEHOLDER_PREFIX + i + _FORMULA_PLACEHOLDER_SUFFIX).join(escaped);
  }
  return html;
}
function _renderMarkdown(mdText) {
  if (!mdText) return "";
  var stashed = _stashFormulas(mdText);
  var rawHtml = marked.parse(stashed.text, { breaks: true });
  return DOMPurify.sanitize(_restoreFormulas(rawHtml, stashed.formulas));
}
function _activateKaTeX(element) {
  if (typeof renderMathInElement !== "function") return;
  renderMathInElement(element, {
    delimiters: [
      { left: "$$", right: "$$", display: true },
      { left: "\\[", right: "\\]", display: true },
      { left: "\\(", right: "\\)", display: false }
    ],
    throwOnError: false
  });
}
function _plainSnippet(mdText, maxLen) {
  maxLen = maxLen || 100;
  if (!mdText) return "";
  var text = mdText
    .replace(/\$\$.+?\$\$/gs, "...")
    .replace(/\\\[.+?\\\]/gs, "...")
    .replace(/\$[^$]+?\$/g, "...")
    .replace(/\\\(.+?\\\)/g, "...")
    .replace(/#{1,6}\s+/g, "")
    .replace(/\*{1,3}(.+?)\*{1,3}/g, "$1")
    .replace(/`{1,3}[^`]*`{1,3}/g, "")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[|:\-]+/g, " ")
    .replace(/\n+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text.length > maxLen ? text.slice(0, maxLen) + "..." : text;
}
window.ICS.render = {
  renderMarkdown: _renderMarkdown,
  activateKaTeX: _activateKaTeX,
  plainSnippet: _plainSnippet
};
