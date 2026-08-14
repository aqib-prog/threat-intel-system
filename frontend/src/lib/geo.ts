import { Vector3 } from "three";

export function latLonToVector3(lat: number, lon: number, radius: number): Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  const x = -radius * Math.sin(phi) * Math.cos(theta);
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new Vector3(x, y, z);
}

export interface City {
  name: string;
  lat: number;
  lon: number;
}

export const THREAT_HUBS: City[] = [
  { name: "New York", lat: 40.7, lon: -74.0 },
  { name: "Sao Paulo", lat: -23.5, lon: -46.6 },
  { name: "London", lat: 51.5, lon: -0.1 },
  { name: "Moscow", lat: 55.75, lon: 37.6 },
  { name: "Lagos", lat: 6.5, lon: 3.4 },
  { name: "Dubai", lat: 25.2, lon: 55.3 },
  { name: "Mumbai", lat: 19.1, lon: 72.9 },
  { name: "Beijing", lat: 39.9, lon: 116.4 },
  { name: "Tokyo", lat: 35.7, lon: 139.7 },
  { name: "Singapore", lat: 1.35, lon: 103.8 },
  { name: "Sydney", lat: -33.9, lon: 151.2 },
  { name: "San Francisco", lat: 37.8, lon: -122.4 },
];

export const ATTACK_ROUTES: [number, number][] = [
  [0, 6], // NY -> Beijing
  [3, 2], // Moscow -> London
  [7, 9], // Beijing -> Singapore
  [4, 5], // Lagos -> Dubai
  [11, 8], // SF -> Tokyo
  [1, 0], // Sao Paulo -> NY
  [6, 10], // Beijing -> Sydney
  [5, 3], // Dubai -> Moscow
];


/**
 * Per-region context shown when a node is probed on the globe.
 *
 * Deliberately real ATT&CK vocabulary - actor names, tactic names, technique
 * ids that exist in the graph - rather than invented telemetry. The globe is
 * the front door of a threat-intel product; putting fake numbers on it would
 * undercut the one thing the product claims, which is that nothing is invented.
 */
export interface RegionIntel {
  actors: string;
  tactic: string;
  technique: string;
}

export const REGION_INTEL: Record<string, RegionIntel> = {
  "New York": { actors: "FIN7 · Carbanak", tactic: "Initial Access", technique: "T1566" },
  "Sao Paulo": { actors: "FIN13", tactic: "Credential Access", technique: "T1110" },
  London: { actors: "APT29 · Wizard Spider", tactic: "Persistence", technique: "T1078" },
  Moscow: { actors: "APT28 · Sandworm", tactic: "Defense Evasion", technique: "T1027" },
  Lagos: { actors: "SilverTerrier", tactic: "Collection", technique: "T1114" },
  Dubai: { actors: "OilRig · MuddyWater", tactic: "Command & Control", technique: "T1071" },
  Mumbai: { actors: "SideWinder", tactic: "Discovery", technique: "T1082" },
  Beijing: { actors: "APT41 · Axiom", tactic: "Lateral Movement", technique: "T1021" },
  Tokyo: { actors: "BlackTech", tactic: "Execution", technique: "T1059" },
  Singapore: { actors: "APT32", tactic: "Exfiltration", technique: "T1041" },
  Sydney: { actors: "APT40", tactic: "Reconnaissance", technique: "T1595" },
  "San Francisco": { actors: "Scattered Spider", tactic: "Privilege Escalation", technique: "T1548" },
};
