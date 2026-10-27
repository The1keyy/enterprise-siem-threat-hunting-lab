export function ArchitectureDiagram() {
  return (
    <svg
      viewBox="0 0 720 280"
      role="img"
      aria-label="Mac console talks to an isolated lab. Agents on DC01, WS01, and UBU01 report to WAZUH01."
      className="h-auto w-full"
    >
      <rect width="720" height="280" fill="var(--color-bg)" />
      <g fill="none" stroke="var(--color-border)" strokeWidth="1">
        <rect x="16" y="24" width="200" height="232" rx="8" />
        <rect x="248" y="24" width="456" height="232" rx="8" />
      </g>
      <text x="28" y="48" fill="var(--color-text-muted)" fontSize="12">
        Mac
      </text>
      <text x="260" y="48" fill="var(--color-text-muted)" fontSize="12">
        Isolated lab 10.10.10.0/24
      </text>
      <g fontSize="13" fill="var(--color-text)">
        <rect
          x="36"
          y="72"
          width="160"
          height="36"
          rx="6"
          fill="var(--color-surface)"
          stroke="var(--color-border)"
        />
        <text x="48" y="94">
          React console
        </text>
        <rect
          x="36"
          y="124"
          width="160"
          height="36"
          rx="6"
          fill="var(--color-surface)"
          stroke="var(--color-border)"
        />
        <text x="48" y="146">
          FastAPI
        </text>
        <rect
          x="268"
          y="88"
          width="120"
          height="44"
          rx="6"
          fill="var(--color-surface)"
          stroke="var(--color-border)"
        />
        <text x="280" y="106">
          DC01
        </text>
        <text x="280" y="122" fill="var(--color-text-muted)" fontSize="11">
          10.10.10.10
        </text>
        <rect
          x="408"
          y="88"
          width="120"
          height="44"
          rx="6"
          fill="var(--color-surface)"
          stroke="var(--color-border)"
        />
        <text x="420" y="106">
          WS01
        </text>
        <text x="420" y="122" fill="var(--color-text-muted)" fontSize="11">
          10.10.10.20
        </text>
        <rect
          x="548"
          y="88"
          width="120"
          height="44"
          rx="6"
          fill="var(--color-surface)"
          stroke="var(--color-border)"
        />
        <text x="560" y="106">
          UBU01
        </text>
        <text x="560" y="122" fill="var(--color-text-muted)" fontSize="11">
          10.10.10.30
        </text>
        <rect
          x="408"
          y="176"
          width="160"
          height="48"
          rx="6"
          fill="var(--color-surface)"
          stroke="var(--color-border)"
        />
        <text x="420" y="196">
          WAZUH01
        </text>
        <text x="420" y="212" fill="var(--color-text-muted)" fontSize="11">
          10.10.10.40
        </text>
      </g>
      <path
        d="M196 142 H248"
        stroke="var(--color-text-muted)"
        strokeDasharray="4 4"
        fill="none"
      />
      <path
        d="M328 132 V176 H408 M468 132 V176 M608 132 V176 H568"
        stroke="var(--color-border)"
        fill="none"
      />
    </svg>
  )
}
