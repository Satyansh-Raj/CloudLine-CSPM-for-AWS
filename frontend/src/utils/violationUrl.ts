/**
 * Helpers for encoding/decoding violation detail page URLs.
 *
 * URL format: /violations/:checkId/:encodedResource
 * e.g.  /violations/s3_01/arn%3Aaws%3As3%3A%3A%3Abucket-1
 */

export function toViolationPath(
  checkId: string,
  resource: string,
): string {
  return `/violations/${encodeURIComponent(checkId)}/${encodeURIComponent(resource)}`;
}

export function fromViolationResource(
  encodedResource: string,
): string {
  return decodeURIComponent(encodedResource);
}
