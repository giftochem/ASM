import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmDialog } from "./ConfirmDialog";

describe("ConfirmDialog", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <ConfirmDialog open={false} title="Test" onConfirm={vi.fn()} onCancel={vi.fn()} />,
    );
    expect(container.textContent).toBe("");
  });

  it("calls onConfirm and onCancel", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(<ConfirmDialog open title="Test dialog" onConfirm={onConfirm} onCancel={onCancel} />);

    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("disables the confirm button when confirmDisabled is true", () => {
    render(<ConfirmDialog open title="Test" onConfirm={vi.fn()} onCancel={vi.fn()} confirmDisabled />);
    expect(screen.getByRole("button", { name: "Confirm" })).toBeDisabled();
  });
});
