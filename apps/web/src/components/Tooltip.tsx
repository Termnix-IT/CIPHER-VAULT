import { useEffect, useLayoutEffect, useRef, useState } from "react";

const HOVER_DELAY_MS = 450;
const GAP = 6;
const MARGIN = 8;

type Shown = { text: string; target: Element };

/**
 * One tooltip for every element with data-tooltip, such as the icon-only title bar and the
 * collapsed list. It is drawn above the page with fixed positioning, so a scrolling list never
 * clips it. data-tooltip-side="right" places it beside the element instead of below.
 * The element keeps its own aria-label; the tooltip only shows the same name to the eye.
 */
export function Tooltip() {
  const [shown, setShown] = useState<Shown | null>(null);
  const element = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let timer: number | undefined;
    const target = (event: Event) => event.target instanceof Element ? event.target.closest("[data-tooltip]") : null;
    const show = (node: Element, delay: number) => {
      window.clearTimeout(timer);
      // An open menu already says what its button does.
      if (node.getAttribute("aria-expanded") === "true") return;
      timer = window.setTimeout(() => {
        const text = node.getAttribute("data-tooltip");
        if (text && node.isConnected) setShown({ text, target: node });
      }, delay);
    };
    const hide = () => { window.clearTimeout(timer); setShown(null); };
    const over = (event: PointerEvent) => { const node = target(event); if (node) show(node, HOVER_DELAY_MS); };
    const out = (event: PointerEvent) => { const node = target(event); if (node && !(event.relatedTarget instanceof Node && node.contains(event.relatedTarget))) hide(); };
    const focus = (event: FocusEvent) => { const node = target(event); if (node instanceof HTMLElement && node.matches(":focus-visible")) show(node, 0); };
    const key = (event: KeyboardEvent) => { if (event.key === "Escape") hide(); };
    document.addEventListener("pointerover", over);
    document.addEventListener("pointerout", out);
    document.addEventListener("focusin", focus);
    document.addEventListener("focusout", hide);
    document.addEventListener("pointerdown", hide, true);
    document.addEventListener("click", hide, true);
    document.addEventListener("keydown", key, true);
    document.addEventListener("scroll", hide, true);
    window.addEventListener("blur", hide);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("pointerover", over);
      document.removeEventListener("pointerout", out);
      document.removeEventListener("focusin", focus);
      document.removeEventListener("focusout", hide);
      document.removeEventListener("pointerdown", hide, true);
      document.removeEventListener("click", hide, true);
      document.removeEventListener("keydown", key, true);
      document.removeEventListener("scroll", hide, true);
      window.removeEventListener("blur", hide);
    };
  }, []);

  // The element can change under the tooltip, such as a row whose name goes when the list unfolds.
  useEffect(() => {
    if (!shown) return;
    const timer = window.setInterval(() => {
      if (!shown.target.isConnected || shown.target.getAttribute("data-tooltip") !== shown.text) setShown(null);
    }, 250);
    return () => window.clearInterval(timer);
  }, [shown]);

  useLayoutEffect(() => {
    const tip = element.current;
    if (!shown || !tip) return;
    const anchor = shown.target.getBoundingClientRect();
    const { width, height } = tip.getBoundingClientRect();
    const right = shown.target.getAttribute("data-tooltip-side") === "right";
    let left = right ? anchor.right + GAP : anchor.left + anchor.width / 2 - width / 2;
    let top = right ? anchor.top + anchor.height / 2 - height / 2 : anchor.bottom + GAP;
    left = Math.max(MARGIN, Math.min(left, window.innerWidth - width - MARGIN));
    if (top + height > window.innerHeight - MARGIN) top = anchor.top - height - GAP;
    tip.style.left = `${left}px`;
    tip.style.top = `${Math.max(MARGIN, top)}px`;
    tip.style.visibility = "visible";
  }, [shown]);

  return shown ? <div className="tooltip" ref={element} role="tooltip" aria-hidden="true">{shown.text}</div> : null;
}
