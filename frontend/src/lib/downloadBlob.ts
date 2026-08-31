/**
 * Triggers a browser "save file" using the standard temporary-object-URL
 * + synthetic-click pattern. Kept separate from api/client.ts — this is
 * DOM/browser mechanics, not networking.
 */
export function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
