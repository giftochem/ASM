import type { ReactNode } from "react";
import { ApiErrorAlert } from "./ApiErrorAlert";

export interface DataTableColumn<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  isLoading?: boolean;
  error?: unknown;
  emptyMessage?: string;
  onRowClick?: (row: T) => void;
}

// Generic paginated-list table — reused by Findings, and intended for
// future Audit Logs / Users list views that share the same shape
// (server-side filtered/paginated, org-scoped rows).
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  isLoading = false,
  error,
  emptyMessage = "No results.",
  onRowClick,
}: DataTableProps<T>) {
  if (isLoading) {
    return <p className="text-sm text-slate-500">Loading...</p>;
  }
  if (error) {
    return <ApiErrorAlert error={error} />;
  }
  if (rows.length === 0) {
    return <p className="text-sm text-slate-500">{emptyMessage}</p>;
  }

  return (
    <div className="overflow-x-auto rounded border">
      <table className="w-full text-left text-sm">
        <thead className="bg-slate-50">
          <tr>
            {columns.map((column) => (
              <th key={column.key} className="px-3 py-2 font-medium text-slate-600">
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={onRowClick ? "cursor-pointer hover:bg-slate-50" : undefined}
            >
              {columns.map((column) => (
                <td key={column.key} className="px-3 py-2">
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
