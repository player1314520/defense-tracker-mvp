const TRUSTED_CLIENT_IP_HEADER = "x-v9-client-ip";

function canonicalIpv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const canonical = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    canonical.push(String(octet));
  }
  return canonical.join(".");
}

function canonicalIpv6(value) {
  if (!value.includes(":")) return null;
  if (!/^[0-9a-f:.]+$/iu.test(value)) return null;
  try {
    const hostname = new URL(`http://[${value}]/`).hostname;
    if (!hostname.startsWith("[") || !hostname.endsWith("]")) return null;
    return hostname.slice(1, -1).toLowerCase();
  } catch {
    return null;
  }
}

// X-V9-Client-IP is accepted only under the deployment contract where the
// trusted reverse proxy removes every client copy and overwrites one value.
// Missing/malformed values deliberately collapse into the global fallback
// bucket; browser-controlled forwarding headers are never consulted here.
export function trustedRequestSource(headers) {
  const raw = headers.get(TRUSTED_CLIENT_IP_HEADER);
  if (
    typeof raw !== "string" ||
    raw.length === 0 ||
    raw.length > 64 ||
    raw !== raw.trim() ||
    raw.includes(",")
  ) {
    return "unavailable";
  }
  return canonicalIpv4(raw) || canonicalIpv6(raw) || "unavailable";
}
