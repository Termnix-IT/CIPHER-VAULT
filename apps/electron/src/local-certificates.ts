import { X509Certificate } from "node:crypto";

const begin = Buffer.from("-----BEGIN CERTIFICATE-----"), end = Buffer.from("-----END CERTIFICATE-----");
// Only a single certificate or a direct leaf/issuer chain is accepted. No ASN.1 or signature implementation.
export function parseLocalPublicCertificate(input: Buffer) {
  if (!Buffer.isBuffer(input) || input.length < 1 || input.length > 16384) throw new Error("Invalid local certificate");
  const certificates: X509Certificate[] = [];
  let offset = 0;
  if (input.subarray(0, begin.length).equals(begin)) {
    while (offset < input.length && input.subarray(offset, offset + begin.length).equals(begin)) {
      const last = input.indexOf(end, offset + begin.length);
      if (last < 0 || certificates.length >= 2) throw new Error("Invalid local certificate chain");
      certificates.push(new X509Certificate(input.subarray(offset, last + end.length)));
      offset = last + end.length;
      while (offset < input.length && [9, 10, 13, 32].includes(input[offset])) offset++;
    }
    // Other PEM material is discarded, never copied into the public certificate storage.
    if (input.indexOf(begin, offset) >= 0) throw new Error("Invalid local certificate chain");
  } else certificates.push(new X509Certificate(input));
  const leaf = certificates[0], issuer = certificates[1];
  if (!leaf) throw new Error("Missing local certificate");
  const from = Date.parse(leaf.validFrom), until = Date.parse(leaf.validTo);
  if (!Number.isSafeInteger(from) || from <= 0 || !Number.isSafeInteger(until) || from >= until) throw new Error("Invalid local certificate lifetime");
  if (issuer && (leaf.ca || !issuer.ca || leaf.fingerprint256 === issuer.fingerprint256 || !leaf.checkIssued(issuer) || !leaf.verify(issuer.publicKey) ||
      issuer.issuer !== issuer.subject || !issuer.verify(issuer.publicKey) || Date.parse(issuer.validFrom) > from || Date.parse(issuer.validTo) < until)) throw new Error("Invalid local certificate issuer");
  const certificate = Buffer.from(certificates.map(value => value.toString()).join(""));
  return { certificate, der: Buffer.from(leaf.raw), stored: issuer ? Buffer.from(certificate) : Buffer.from(leaf.raw),
    fingerprint: leaf.fingerprint256, from, until, leaf, issuer };
}
