export interface KemRow {
  family: "HQC" | "BIKE" | "ML-KEM";
  level: "L1" | "L3" | "L5";
  variant: string;
  publicKeyBytes: number;
  ciphertextBytes: number;
  sharedSecretBytes: number;
  keygenKCycles: number | null;
  encapKCycles: number | null;
  decapKCycles: number | null;
  assumption: string;
  correctness: string;
  source: string;
}

export const comparisonRows: KemRow[] = [
  {
    family: "HQC",
    level: "L1",
    variant: "HQC-128",
    publicKeyBytes: 2249,
    ciphertextBytes: 4497,
    sharedSecretBytes: 64,
    keygenKCycles: 87,
    encapKCycles: 204,
    decapKCycles: 362,
    assumption: "QCSD/DSD over quasi-cyclic codes",
    correctness: "Perfect correctness",
    source: "HQC Round-4 submission (Table 6, Table 9)"
  },
  {
    family: "BIKE",
    level: "L1",
    variant: "BIKE-1",
    publicKeyBytes: 1541,
    ciphertextBytes: 1573,
    sharedSecretBytes: 32,
    keygenKCycles: 589,
    encapKCycles: 97,
    decapKCycles: 1135,
    assumption: "QC-MDPC decoding/codeword finding",
    correctness: "Non-zero DFR target 2^-128",
    source: "BIKE Round-4 spec (Table 5, Table 7 AVX512)"
  },
  {
    family: "ML-KEM",
    level: "L1",
    variant: "ML-KEM-512",
    publicKeyBytes: 800,
    ciphertextBytes: 768,
    sharedSecretBytes: 32,
    keygenKCycles: 34,
    encapKCycles: 45,
    decapKCycles: 35,
    assumption: "Module-LWE",
    correctness: "Deterministic decapsulation in standardized flow",
    source: "CRYSTALS-Kyber site (Haswell AVX2 cycles)"
  },
  {
    family: "HQC",
    level: "L3",
    variant: "HQC-192",
    publicKeyBytes: 4522,
    ciphertextBytes: 9042,
    sharedSecretBytes: 64,
    keygenKCycles: 204,
    encapKCycles: 465,
    decapKCycles: 755,
    assumption: "QCSD/DSD over quasi-cyclic codes",
    correctness: "Perfect correctness",
    source: "HQC Round-4 submission (Table 6, Table 9)"
  },
  {
    family: "BIKE",
    level: "L3",
    variant: "BIKE-3",
    publicKeyBytes: 3083,
    ciphertextBytes: 3115,
    sharedSecretBytes: 32,
    keygenKCycles: 1823,
    encapKCycles: 223,
    decapKCycles: 3887,
    assumption: "QC-MDPC decoding/codeword finding",
    correctness: "Non-zero DFR target 2^-192",
    source: "BIKE Round-4 spec (Table 5, Table 8 AVX512)"
  },
  {
    family: "ML-KEM",
    level: "L3",
    variant: "ML-KEM-768",
    publicKeyBytes: 1184,
    ciphertextBytes: 1088,
    sharedSecretBytes: 32,
    keygenKCycles: 53,
    encapKCycles: 68,
    decapKCycles: 53,
    assumption: "Module-LWE",
    correctness: "Deterministic decapsulation in standardized flow",
    source: "CRYSTALS-Kyber site (Haswell AVX2 cycles)"
  },
  {
    family: "HQC",
    level: "L5",
    variant: "HQC-256",
    publicKeyBytes: 7245,
    ciphertextBytes: 14485,
    sharedSecretBytes: 64,
    keygenKCycles: 409,
    encapKCycles: 904,
    decapKCycles: 1505,
    assumption: "QCSD/DSD over quasi-cyclic codes",
    correctness: "Perfect correctness",
    source: "HQC Round-4 submission (Table 6, Table 9)"
  },
  {
    family: "BIKE",
    level: "L5",
    variant: "BIKE-5",
    publicKeyBytes: 5122,
    ciphertextBytes: 5154,
    sharedSecretBytes: 32,
    keygenKCycles: null,
    encapKCycles: null,
    decapKCycles: null,
    assumption: "QC-MDPC decoding/codeword finding",
    correctness: "Non-zero DFR target 2^-256",
    source: "BIKE Round-4 spec (Table 4 and Table 5; no L5 software cycles table)"
  },
  {
    family: "ML-KEM",
    level: "L5",
    variant: "ML-KEM-1024",
    publicKeyBytes: 1568,
    ciphertextBytes: 1568,
    sharedSecretBytes: 32,
    keygenKCycles: 74,
    encapKCycles: 97,
    decapKCycles: 79,
    assumption: "Module-LWE",
    correctness: "Deterministic decapsulation in standardized flow",
    source: "CRYSTALS-Kyber site (Haswell AVX2 cycles)"
  }
];

function cycleLabel(value: number | null): string {
  return value === null ? "N/A" : `${value}k`;
}

export function buildComparisonRows(): string {
  return comparisonRows
    .map(
      (row) => `
      <tr>
        <td>${row.variant}</td>
        <td>${row.publicKeyBytes}</td>
        <td>${row.ciphertextBytes}</td>
        <td>${row.sharedSecretBytes}</td>
        <td>${cycleLabel(row.keygenKCycles)}</td>
        <td>${cycleLabel(row.encapKCycles)}</td>
        <td>${cycleLabel(row.decapKCycles)}</td>
        <td>${row.assumption}</td>
        <td>${row.correctness}</td>
      </tr>`
    )
    .join("");
}

export function buildBarChartRows(level: "L1" | "L3" | "L5"): string {
  const selected = comparisonRows.filter((row) => row.level === level);
  const max = Math.max(...selected.map((row) => row.publicKeyBytes + row.ciphertextBytes));

  return selected
    .map((row) => {
      const sum = row.publicKeyBytes + row.ciphertextBytes;
      const width = Math.max(8, Math.round((sum / max) * 100));
      return `
      <div class="bar-row" role="listitem" aria-label="${row.variant} total key plus ciphertext size ${sum} bytes">
        <span class="bar-label">${row.variant}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:${width}%"></div>
        </div>
        <span class="bar-value">${sum} B</span>
      </div>`;
    })
    .join("");
}

export function buildSourcesList(): string {
  const unique = Array.from(new Set(comparisonRows.map((row) => row.source)));
  return unique.map((s) => `<li>${s}</li>`).join("");
}
