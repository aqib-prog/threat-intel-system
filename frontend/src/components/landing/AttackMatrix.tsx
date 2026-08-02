import { useLayoutEffect, useRef, useState } from "react";
import gsap from "gsap";
import { useReducedMotion } from "../../hooks/useReducedMotion";

/**
 * The landing page's signature element: the ATT&CK matrix rendered as a floor
 * plane receding toward a horizon, with an adversary path igniting tactic by
 * tactic into the distance.
 *
 * The motion is the subject, not decoration - each ignition is one hop along a
 * real kill chain (Reconnaissance -> ... -> Impact), which is exactly what this
 * product does: traverse a graph of tactics and techniques. Every tactic and
 * technique id below is real MITRE ATT&CK Enterprise data.
 */

interface Tactic {
  id: string;
  name: string;
  techniques: [string, string][]; // [external_id, name]
}

// Real ATT&CK Enterprise tactics in kill-chain order.
const TACTICS: Tactic[] = [
  { id: "TA0043", name: "Reconnaissance", techniques: [["T1595", "Active Scanning"], ["T1592", "Gather Victim Host Information"], ["T1589", "Gather Victim Identity Information"], ["T1590", "Gather Victim Network Information"], ["T1598", "Phishing for Information"]] },
  { id: "TA0042", name: "Resource Development", techniques: [["T1583", "Acquire Infrastructure"], ["T1587", "Develop Capabilities"], ["T1588", "Obtain Capabilities"], ["T1585", "Establish Accounts"], ["T1608", "Stage Capabilities"]] },
  { id: "TA0001", name: "Initial Access", techniques: [["T1566", "Phishing"], ["T1190", "Exploit Public-Facing Application"], ["T1133", "External Remote Services"], ["T1078", "Valid Accounts"], ["T1189", "Drive-by Compromise"]] },
  { id: "TA0002", name: "Execution", techniques: [["T1059", "Command and Scripting Interpreter"], ["T1053", "Scheduled Task/Job"], ["T1047", "Windows Management Instrumentation"], ["T1203", "Exploitation for Client Execution"], ["T1204", "User Execution"]] },
  { id: "TA0003", name: "Persistence", techniques: [["T1547", "Boot or Logon Autostart Execution"], ["T1136", "Create Account"], ["T1505", "Server Software Component"], ["T1543", "Create or Modify System Process"], ["T1546", "Event Triggered Execution"]] },
  { id: "TA0004", name: "Privilege Escalation", techniques: [["T1068", "Exploitation for Privilege Escalation"], ["T1548", "Abuse Elevation Control Mechanism"], ["T1134", "Access Token Manipulation"], ["T1055", "Process Injection"], ["T1484", "Domain Policy Modification"]] },
  { id: "TA0005", name: "Defense Evasion", techniques: [["T1070", "Indicator Removal"], ["T1027", "Obfuscated Files or Information"], ["T1036", "Masquerading"], ["T1562", "Impair Defenses"], ["T1218", "System Binary Proxy Execution"]] },
  { id: "TA0006", name: "Credential Access", techniques: [["T1003", "OS Credential Dumping"], ["T1110", "Brute Force"], ["T1555", "Credentials from Password Stores"], ["T1552", "Unsecured Credentials"], ["T1558", "Steal or Forge Kerberos Tickets"]] },
  { id: "TA0007", name: "Discovery", techniques: [["T1082", "System Information Discovery"], ["T1057", "Process Discovery"], ["T1018", "Remote System Discovery"], ["T1083", "File and Directory Discovery"], ["T1087", "Account Discovery"]] },
  { id: "TA0008", name: "Lateral Movement", techniques: [["T1021", "Remote Services"], ["T1550", "Use Alternate Authentication Material"], ["T1570", "Lateral Tool Transfer"], ["T1080", "Taint Shared Content"], ["T1210", "Exploitation of Remote Services"]] },
  { id: "TA0009", name: "Collection", techniques: [["T1005", "Data from Local System"], ["T1113", "Screen Capture"], ["T1056", "Input Capture"], ["T1114", "Email Collection"], ["T1560", "Archive Collected Data"]] },
  { id: "TA0011", name: "Command and Control", techniques: [["T1071", "Application Layer Protocol"], ["T1105", "Ingress Tool Transfer"], ["T1573", "Encrypted Channel"], ["T1090", "Proxy"], ["T1102", "Web Service"]] },
  { id: "TA0010", name: "Exfiltration", techniques: [["T1041", "Exfiltration Over C2 Channel"], ["T1567", "Exfiltration Over Web Service"], ["T1048", "Exfiltration Over Alternative Protocol"], ["T1030", "Data Transfer Size Limits"], ["T1029", "Scheduled Transfer"]] },
  { id: "TA0040", name: "Impact", techniques: [["T1486", "Data Encrypted for Impact"], ["T1490", "Inhibit System Recovery"], ["T1489", "Service Stop"], ["T1485", "Data Destruction"], ["T1498", "Network Denial of Service"]] },
];

const COLS = 5;
const STEP = 0.42; // seconds between tactic hops
const CYAN = "#00f5ff";

interface Readout {
  tactic: string;
  tacticId: string;
  techniqueId: string;
  technique: string;
  step: number;
}

export function AttackMatrix() {
  const rootRef = useRef<HTMLDivElement>(null);
  const planeRef = useRef<HTMLDivElement>(null);
  const cellRefs = useRef<(HTMLSpanElement | null)[][]>(
    TACTICS.map(() => Array(COLS).fill(null))
  );
  const reduced = useReducedMotion();
  const [readout, setReadout] = useState<Readout | null>(null);

  useLayoutEffect(() => {
    const context = gsap.context(() => {
      const cells = cellRefs.current.flat().filter(Boolean) as HTMLSpanElement[];
      if (!cells.length) return;

      // The receding-floor tilt is owned by GSAP (not inline CSS) so the pointer
      // parallax below can drive the same transform without fighting it.
      gsap.set(planeRef.current, { rotationX: 58, rotation: -6 });

      if (reduced) {
        // Static, legible grid: no propagation, no parallax.
        gsap.set(cells, { opacity: 0.16 });
        setReadout({
          tactic: TACTICS[2].name,
          tacticId: TACTICS[2].id,
          techniqueId: TACTICS[2].techniques[0][0],
          technique: TACTICS[2].techniques[0][1],
          step: 3,
        });
        return;
      }

      gsap.set(cells, { opacity: 0 });

      // Entrance: the plane builds from the foreground toward the horizon, so
      // the grid reads as ground being surveyed rather than a fade-in.
      gsap.to(cells, {
        opacity: 0.14,
        duration: 0.5,
        ease: "power2.out",
        stagger: { each: 0.008, from: "start" },
      });

      // One pass = one adversary walking the kill chain, front to horizon.
      const runPath = () => {
        const path = TACTICS.map(() => Math.floor(Math.random() * COLS));
        const timeline = gsap.timeline({
          delay: 0.7,
          onComplete: () => {
            gsap.delayedCall(1.1, runPath);
          },
        });

        path.forEach((col, row) => {
          const cell = cellRefs.current[row][col];
          if (!cell) return;
          const at = row * STEP;

          timeline.to(
            cell,
            {
              opacity: 1,
              backgroundColor: CYAN,
              boxShadow: `0 0 18px ${CYAN}, 0 0 42px rgba(0,245,255,0.55)`,
              duration: 0.18,
              ease: "power3.out",
              onStart: () => {
                const [techniqueId, technique] = TACTICS[row].techniques[col];
                setReadout({
                  tactic: TACTICS[row].name,
                  tacticId: TACTICS[row].id,
                  techniqueId,
                  technique,
                  step: row + 1,
                });
              },
            },
            at
          );

          // Comet tail: the hop stays hot briefly, then decays to a warm ember
          // so the traversed path remains readable behind the leading edge.
          timeline.to(
            cell,
            {
              opacity: 0.34,
              backgroundColor: "rgba(0,245,255,0.30)",
              boxShadow: "0 0 0 rgba(0,245,255,0)",
              duration: 1.5,
              ease: "power2.out",
            },
            at + 0.3
          );

          // Reset to the resting grid before the next adversary walks through.
          timeline.to(
            cell,
            { opacity: 0.14, backgroundColor: "rgba(0,245,255,0.06)", duration: 0.9 },
            TACTICS.length * STEP + 0.6
          );
        });
      };

      runPath();

      // Pointer parallax: the plane answers the cursor, giving the depth a
      // physical feel without moving anything the eye is trying to read.
      const plane = planeRef.current;
      const root = rootRef.current;
      if (!plane || !root) return;
      // GSAP transform props are rotationX / rotation (z) - NOT rotateX/rotateZ,
      // which GSAP cannot read or revert and which silently break the context.
      const quickZ = gsap.quickTo(plane, "rotation", { duration: 0.9, ease: "power3.out" });
      const quickX = gsap.quickTo(plane, "rotationX", { duration: 0.9, ease: "power3.out" });
      const onMove = (event: PointerEvent) => {
        const rect = root.getBoundingClientRect();
        const dx = (event.clientX - (rect.left + rect.width / 2)) / rect.width;
        const dy = (event.clientY - (rect.top + rect.height / 2)) / rect.height;
        quickZ(-6 + dx * 7);
        quickX(58 - dy * 5);
      };
      window.addEventListener("pointermove", onMove, { passive: true });
      return () => window.removeEventListener("pointermove", onMove);
    }, rootRef);

    return () => context.revert();
  }, [reduced]);

  return (
    <div ref={rootRef} className="relative h-full w-full select-none overflow-hidden">
      {/* Horizon glow the path recedes into. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-[14%] h-40 opacity-70"
        style={{
          background:
            "radial-gradient(ellipse 60% 100% at 50% 100%, rgba(0,245,255,0.16), transparent 70%)",
        }}
      />

      <div
        className="absolute inset-0 flex items-end justify-center pb-10"
        style={{ perspective: "760px", perspectiveOrigin: "50% 38%" }}
      >
        <div
          ref={planeRef}
          className="grid gap-[6px]"
          style={{
            gridTemplateColumns: `repeat(${COLS}, 46px)`,
            transformStyle: "preserve-3d",
            maskImage: "linear-gradient(to top, #000 22%, rgba(0,0,0,0.65) 55%, transparent 92%)",
            WebkitMaskImage: "linear-gradient(to top, #000 22%, rgba(0,0,0,0.65) 55%, transparent 92%)",
          }}
        >
          {TACTICS.map((tactic, row) =>
            Array.from({ length: COLS }, (_, col) => (
              <span
                key={`${tactic.id}-${col}`}
                ref={(el) => {
                  cellRefs.current[row][col] = el;
                }}
                className="block h-[26px] rounded-[3px] border border-cyan/15"
                style={{ backgroundColor: "rgba(0,245,255,0.06)" }}
              />
            ))
          )}
        </div>
      </div>

      {/* Live readout - names the hop the eye is watching, so the motion is
          information rather than ambience. */}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 px-1">
        <div className="flex items-baseline gap-2 font-mono text-[10px] uppercase tracking-[0.24em] text-text-dim">
          <span className="h-1.5 w-1.5 rounded-full bg-cyan motion-safe:animate-pulse" />
          Live attack path
          <span className="ml-auto tabular-nums">
            {readout ? String(readout.step).padStart(2, "0") : "--"}/{TACTICS.length}
          </span>
        </div>
        <p className="mt-1.5 truncate font-display text-sm font-semibold text-cyan">
          {readout ? readout.tactic : "Awaiting telemetry"}
          {readout && (
            <span className="ml-1.5 font-mono text-[11px] font-normal text-text-dim">
              {readout.tacticId}
            </span>
          )}
        </p>
        <p className="mt-0.5 truncate font-mono text-[11px] text-text-mid">
          {readout ? `${readout.techniqueId} · ${readout.technique}` : "—"}
        </p>
      </div>
    </div>
  );
}
