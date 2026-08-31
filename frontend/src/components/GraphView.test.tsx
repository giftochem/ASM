import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { GraphView } from "./GraphView";
import type { GraphEdge, GraphNode } from "../api/assets";

const SEED_ID = "11111111-1111-1111-1111-111111111111";
const NEIGHBOR_ID = "22222222-2222-2222-2222-222222222222";

function makeNode(overrides: Partial<GraphNode>): GraphNode {
  return {
    id: SEED_ID,
    asset_type: "domain",
    value: "example.com",
    status: "active",
    source: "manual",
    confidence: 1.0,
    environment: null,
    criticality: null,
    owner: null,
    tags: [],
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

const seedNode = makeNode({ id: SEED_ID, value: "example.com" });
const neighborNode = makeNode({ id: NEIGHBOR_ID, asset_type: "subdomain", value: "www.example.com" });
const edge: GraphEdge = {
  id: "edge-1",
  source_asset_id: SEED_ID,
  target_asset_id: NEIGHBOR_ID,
  relationship_type: "belongs_to",
  status: "active",
  confidence: 0.9,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

describe("GraphView", () => {
  it("shows an empty state when there are no nodes", () => {
    render(<GraphView nodes={[]} edges={[]} seedAssetId={SEED_ID} />);
    expect(screen.getByText(/no relationships to display/i)).toBeInTheDocument();
  });

  it("renders one labeled, clickable element per node and a line per edge", () => {
    render(<GraphView nodes={[seedNode, neighborNode]} edges={[edge]} seedAssetId={SEED_ID} onNodeClick={() => {}} />);

    const graph = screen.getByRole("img", { name: /attack surface graph/i });
    expect(within(graph).getByRole("button", { name: /example\.com \(domain\)/i })).toBeInTheDocument();
    expect(within(graph).getByRole("button", { name: /www\.example\.com \(subdomain\)/i })).toBeInTheDocument();
    expect(graph.querySelectorAll("line")).toHaveLength(1);
  });

  it("calls onNodeClick with the clicked node when a node is clicked", async () => {
    const handleClick = vi.fn();
    render(<GraphView nodes={[seedNode, neighborNode]} edges={[edge]} seedAssetId={SEED_ID} onNodeClick={handleClick} />);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /www\.example\.com \(subdomain\)/i }));

    expect(handleClick).toHaveBeenCalledWith(neighborNode);
  });

  it("calls onNodeClick when a node is activated via keyboard (Enter)", async () => {
    const handleClick = vi.fn();
    render(<GraphView nodes={[seedNode, neighborNode]} edges={[edge]} seedAssetId={SEED_ID} onNodeClick={handleClick} />);
    const user = userEvent.setup();

    const node = screen.getByRole("button", { name: /www\.example\.com \(subdomain\)/i });
    node.focus();
    await user.keyboard("{Enter}");

    expect(handleClick).toHaveBeenCalledWith(neighborNode);
  });

  it("does not make nodes clickable/focusable when onNodeClick is omitted", () => {
    render(<GraphView nodes={[seedNode, neighborNode]} edges={[edge]} seedAssetId={SEED_ID} />);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("drops an edge that references a node not present in the current node set", () => {
    // A dangling edge shouldn't happen given the backend's own induced-
    // subgraph guarantee, but the component must not crash if it does.
    const danglingEdge: GraphEdge = { ...edge, target_asset_id: "does-not-exist" };
    render(<GraphView nodes={[seedNode]} edges={[danglingEdge]} seedAssetId={SEED_ID} />);
    const graph = screen.getByRole("img", { name: /attack surface graph/i });
    expect(graph.querySelectorAll("line")).toHaveLength(0);
  });
});
