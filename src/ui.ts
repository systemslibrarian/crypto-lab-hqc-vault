export function setupLevelSelector(onChange: (value: "L1" | "L3" | "L5") => void): void {
  const select = document.querySelector<HTMLSelectElement>("#compare-level");
  if (!select) return;
  const apply = () => onChange(select.value as "L1" | "L3" | "L5");
  select.addEventListener("change", apply);
  apply();
}

export function announce(message: string): void {
  const live = document.querySelector<HTMLDivElement>("#live-region");
  if (!live) return;
  live.textContent = "";
  requestAnimationFrame(() => {
    live.textContent = message;
  });
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// Wrap a string of inline HTML so glossary terms are clickable.
// Caller passes already-safe markup; glossary terms use [[term]] syntax to mark spots.
export function withGlossary(markup: string): string {
  return markup.replace(/\[\[([^\]]+)\]\]/g, (_m, term) => {
    const safe = escapeHtml(term);
    return `<button type="button" class="gloss" data-term="${safe.toLowerCase()}" aria-label="Define ${safe}">${safe}</button>`;
  });
}

export interface GlossTerm {
  short: string;
  long: string;
}

let glossaryPopover: HTMLDivElement | null = null;
let glossaryTerms: Record<string, GlossTerm> = {};

function ensurePopover(): HTMLDivElement {
  if (glossaryPopover) return glossaryPopover;
  const el = document.createElement("div");
  el.className = "gloss-popover";
  el.setAttribute("role", "dialog");
  el.setAttribute("aria-live", "polite");
  el.hidden = true;
  document.body.appendChild(el);
  glossaryPopover = el;
  document.addEventListener("click", (ev) => {
    const target = ev.target as HTMLElement | null;
    if (!target) return;
    if (target.closest(".gloss") || target.closest(".gloss-popover")) return;
    el.hidden = true;
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") el.hidden = true;
  });
  return el;
}

export function setupGlossary(terms: Record<string, GlossTerm>): void {
  glossaryTerms = terms;
  const popover = ensurePopover();
  document.addEventListener("click", (ev) => {
    const target = ev.target as HTMLElement | null;
    const btn = target?.closest<HTMLButtonElement>(".gloss");
    if (!btn) return;
    ev.preventDefault();
    const key = btn.dataset.term;
    if (!key) return;
    const term = glossaryTerms[key];
    if (!term) return;
    popover.innerHTML = `
      <h4>${escapeHtml(term.short)}</h4>
      <p>${escapeHtml(term.long)}</p>
      <button type="button" class="gloss-close" aria-label="Close definition">Close</button>
    `;
    const closeBtn = popover.querySelector<HTMLButtonElement>(".gloss-close");
    closeBtn?.addEventListener("click", () => {
      popover.hidden = true;
      btn.focus();
    });
    popover.hidden = false;
    const rect = btn.getBoundingClientRect();
    const popRect = popover.getBoundingClientRect();
    const top = window.scrollY + rect.bottom + 6;
    let left = window.scrollX + rect.left;
    if (left + popRect.width > window.scrollX + window.innerWidth - 12) {
      left = window.scrollX + window.innerWidth - popRect.width - 12;
    }
    popover.style.top = `${top}px`;
    popover.style.left = `${left}px`;
    closeBtn?.focus();
  });
}

export function setupCopyButtons(): void {
  document.addEventListener("click", async (ev) => {
    const target = ev.target as HTMLElement | null;
    const btn = target?.closest<HTMLButtonElement>("[data-copy-target]");
    if (!btn) return;
    const sel = btn.dataset.copyTarget;
    if (!sel) return;
    const node = document.querySelector(sel);
    const text = node?.textContent ?? "";
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const original = btn.textContent;
      btn.textContent = "Copied";
      announce("Copied to clipboard.");
      window.setTimeout(() => {
        btn.textContent = original;
      }, 1200);
    } catch {
      announce("Copy failed.");
    }
  });
}

export interface TocItem {
  id: string;
  label: string;
}

export function setupToc(items: TocItem[]): void {
  const nav = document.querySelector<HTMLElement>("#toc");
  if (!nav) return;
  nav.innerHTML = items
    .map(
      (item) =>
        `<a href="#${item.id}" data-toc="${item.id}">${escapeHtml(item.label)}</a>`
    )
    .join("");

  const links = Array.from(nav.querySelectorAll<HTMLAnchorElement>("a[data-toc]"));
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          const id = entry.target.id;
          links.forEach((link) => {
            link.classList.toggle("active", link.dataset.toc === id);
          });
        }
      }
    },
    { rootMargin: "-30% 0px -55% 0px" }
  );
  for (const item of items) {
    const el = document.getElementById(item.id);
    if (el) observer.observe(el);
  }
}
