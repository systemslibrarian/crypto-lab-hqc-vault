export function setupThemeToggle(): void {
  const root = document.documentElement;
  const btn = document.querySelector<HTMLButtonElement>("#theme-toggle");
  if (!btn) return;

  const stored = localStorage.getItem("hqc-theme");
  const initial = stored === "light" || stored === "dark" ? stored : "dark";
  root.dataset.theme = initial;
  btn.setAttribute("aria-pressed", initial === "dark" ? "true" : "false");
  btn.textContent = initial === "dark" ? "Switch to light mode" : "Switch to dark mode";

  btn.addEventListener("click", () => {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    localStorage.setItem("hqc-theme", next);
    btn.setAttribute("aria-pressed", next === "dark" ? "true" : "false");
    btn.textContent = next === "dark" ? "Switch to light mode" : "Switch to dark mode";
  });
}

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
