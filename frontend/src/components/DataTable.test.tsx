import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DataTable, type DataTableColumn } from "./DataTable";

interface Row {
  id: string;
  name: string;
}

const columns: DataTableColumn<Row>[] = [{ key: "name", header: "Name", render: (r) => r.name }];

describe("DataTable", () => {
  it("shows a loading state", () => {
    render(<DataTable columns={columns} rows={[]} rowKey={(r) => r.id} isLoading />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it("shows an error state instead of an empty table", () => {
    render(<DataTable columns={columns} rows={[]} rowKey={(r) => r.id} error={new Error("boom")} />);
    // ApiErrorAlert renders null for non-ApiError instances — this just
    // proves the table body itself isn't rendered when error is set.
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows the empty message when there are no rows", () => {
    render(<DataTable columns={columns} rows={[]} rowKey={(r) => r.id} emptyMessage="Nothing here." />);
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });

  it("renders rows via each column's render function", () => {
    render(
      <DataTable
        columns={columns}
        rows={[
          { id: "1", name: "Alpha" },
          { id: "2", name: "Beta" },
        ]}
        rowKey={(r) => r.id}
      />,
    );
    expect(screen.getByText("Alpha")).toBeInTheDocument();
    expect(screen.getByText("Beta")).toBeInTheDocument();
  });

  it("calls onRowClick with the clicked row", async () => {
    const onRowClick = vi.fn();
    const user = userEvent.setup();
    render(
      <DataTable columns={columns} rows={[{ id: "1", name: "Alpha" }]} rowKey={(r) => r.id} onRowClick={onRowClick} />,
    );
    await user.click(screen.getByText("Alpha"));
    expect(onRowClick).toHaveBeenCalledWith({ id: "1", name: "Alpha" });
  });
});
