/** Convert updater HTML to text without inserting remote markup into the page. */
export function releaseNotesToText(source: string): string {
  if (!/<(?:\/?[a-z][^>]*|!--[\s\S]*?)>/i.test(source)) return source.trim();

  // Template contents remain inert: scripts, event handlers and resources are not activated.
  const template = document.createElement("template");
  template.innerHTML = source;
  template.content.querySelectorAll("script, style, template, iframe, object, embed, img, video, audio, source, link, meta, noscript")
    .forEach((element) => element.remove());

  const blocks = new Set(["P", "DIV", "SECTION", "ARTICLE", "H1", "H2", "H3", "H4", "H5", "H6", "UL", "OL", "PRE", "BLOCKQUOTE", "TABLE"]);
  const lines = new Set(["LI", "TR", "DT", "DD", "HR"]);
  const chunks: string[] = [];
  const stack: { node: Node; preformatted: boolean; after?: string }[] = [{ node: template.content, preformatted: false }];
  while (stack.length) {
    const { node, preformatted, after } = stack.pop()!;
    if (after !== undefined) { chunks.push(after); continue; }
    if (node.nodeType === Node.TEXT_NODE) {
      chunks.push(preformatted ? node.textContent ?? "" : (node.textContent ?? "").replace(/\s+/g, " "));
      continue;
    }
    if (node.nodeType !== Node.ELEMENT_NODE && node.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) continue;
    const tag = node.nodeType === Node.ELEMENT_NODE ? (node as Element).tagName : "";
    const boundary = blocks.has(tag) ? "\n\n" : lines.has(tag) ? "\n" : "";
    chunks.push(boundary);
    if (tag === "BR") chunks.push("\n");
    if (tag === "LI") chunks.push("• ");
    if (tag === "TD" || tag === "TH") chunks.push(" ");
    if (boundary) stack.push({ node, preformatted, after: boundary });
    for (let index = node.childNodes.length - 1; index >= 0; index--) {
      stack.push({ node: node.childNodes[index], preformatted: preformatted || tag === "PRE" });
    }
  }
  return chunks.join("").replace(/[ \t]+\n/g, "\n").replace(/\n(?:[ \t]*\n){2,}/g, "\n\n")
    .replace(/•[ \t]*\n+[ \t]*/g, "• ").trim();
}
