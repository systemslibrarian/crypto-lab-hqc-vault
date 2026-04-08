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
