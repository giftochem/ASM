import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { triggerBlobDownload } from "./downloadBlob";

// jsdom does not implement URL.createObjectURL/revokeObjectURL at all —
// added directly as static methods on the real URL class rather than
// replacing the global (vi.stubGlobal("URL", {...URL, ...}) spreads the
// class into a plain object and destroys its constructor behavior,
// breaking every `new URL(...)` call elsewhere, including MSW's own
// request interception).
const createObjectURL = vi.fn(() => "blob:mock-url");
const revokeObjectURL = vi.fn();

beforeEach(() => {
  URL.createObjectURL = createObjectURL;
  URL.revokeObjectURL = revokeObjectURL;
  createObjectURL.mockClear();
  revokeObjectURL.mockClear();
});

afterEach(() => {
  // @ts-expect-error — not part of the lib.dom types this project targets in jsdom
  delete URL.createObjectURL;
  // @ts-expect-error — same as above
  delete URL.revokeObjectURL;
});

describe("triggerBlobDownload", () => {
  it("creates an object URL, clicks a download link with the given filename, then revokes it", () => {
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const blob = new Blob(["content"], { type: "application/pdf" });

    triggerBlobDownload(blob, "asm-report-123.pdf");

    expect(createObjectURL).toHaveBeenCalledWith(blob);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");

    clickSpy.mockRestore();
  });

  it("does not leave the temporary anchor element in the document", () => {
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const blob = new Blob(["x"]);

    triggerBlobDownload(blob, "file.csv");

    expect(document.querySelector("a[download='file.csv']")).toBeNull();
  });
});
