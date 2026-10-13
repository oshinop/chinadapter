import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { ApiError } from "./api";
import { chengduDetails, currentConsumerURL, makeApi, nodes, readyStatus } from "./test/fixtures";
import type { NodeDetails, ProbeResult } from "./types";

async function renderAt(path: string, inventory = nodes) {
  window.history.replaceState(null, "", path);
  const api = makeApi(readyStatus(), inventory);
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Service status" });
  await userEvent.click(screen.getByRole("button", { name: "KuaiFan" }));
  await screen.findByRole("tree", { name: "Nodes by group" });
  await waitFor(() => expect(window.location.pathname).toBe("/"));
  return api;
}

async function openGroup(name: string) {
  const group = screen.getByRole("treeitem", { name: `${name} group` });
  expect((group as HTMLDetailsElement).open).toBe(false);
  await userEvent.click(within(group).getByText(name, { exact: true }));
  expect((group as HTMLDetailsElement).open).toBe(true);
  return group;
}

describe("node inventory", () => {
  it("shows upstream node details and copies a SOCKS5 URL only when opened", async () => {
    const api = await renderAt("/nodes");
    const details = { ...chengduDetails, socksUsername: "local:user", socksPassword: "pass/word?value#" };
    vi.mocked(api.nodeDetails).mockResolvedValue(details);
    expect(screen.getAllByText("Shanghai 01").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Chengdu 02").length).toBeGreaterThan(0);
    expect(screen.queryAllByText("Shanghai Archive")).toHaveLength(0);
    expect(screen.queryByText("203.0.113.20:11001")).toBeNull();
    expect(api.nodeDetails).not.toHaveBeenCalled();
    await openGroup("West China");
    const detailButtons = screen.getAllByRole("button", { name: "Details for Chengdu 02" });
    const probeButtons = screen.getAllByRole("button", { name: "Check TCP reachability for Chengdu 02" });
    expect(detailButtons.length).toBeGreaterThan(0);
    expect(probeButtons.length).toBeGreaterThan(0);
    expect(probeButtons[0].querySelector(".lucide-gauge")).toBeTruthy();

    await userEvent.hover(detailButtons[0]);
    expect(await screen.findByRole("tooltip", { name: "Details" })).toBeTruthy();
    await userEvent.hover(probeButtons[0]);
    expect(await screen.findByRole("tooltip", { name: "Check TCP reachability" })).toBeTruthy();

    await userEvent.click(detailButtons[0]);
    expect(api.nodeDetails).toHaveBeenCalledOnce();
    expect(api.nodeDetails).toHaveBeenCalledWith("n-west");
    expect(await screen.findByRole("heading", { name: "Chengdu 02" })).toBeTruthy();
    expect(screen.getByText(`${details.upstreamHost}:${details.upstreamPort}`)).toBeTruthy();
    expect(screen.queryByText("Local SOCKS", { exact: true })).toBeNull();
    expect(screen.queryByText("SOCKS username", { exact: true })).toBeNull();
    expect(screen.queryByText("SOCKS password", { exact: true })).toBeNull();
    expect(screen.getByText("Latency", { exact: true })).toBeTruthy();
    expect(screen.queryByText("Active TCP", { exact: true })).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: "Copy SOCKS5 URL" }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith("socks5://local%3Auser:pass%2Fword%3Fvalue%23@127.0.0.1:10808");
    expect(await screen.findByText("SOCKS5 URL copied.")).toBeTruthy();

    await userEvent.click(detailButtons[0]);
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Chengdu 02" })).toBeNull());
  });

  it("uses the accessible probe action and ignores stale details after close or lock", async () => {
    const api = await renderAt("/");
    await openGroup("West China");
    await userEvent.click(screen.getAllByRole("button", { name: "Check TCP reachability for Chengdu 02" })[0]);
    expect(api.probeNode).toHaveBeenCalledWith("n-west");

    const closedDetails = Promise.withResolvers<NodeDetails>();
    const reopenedDetails = Promise.withResolvers<NodeDetails>();
    vi.mocked(api.nodeDetails)
      .mockReturnValueOnce(closedDetails.promise)
      .mockReturnValueOnce(reopenedDetails.promise);
    const detailButton = screen.getAllByRole("button", { name: "Details for Chengdu 02" })[0];
    await userEvent.click(detailButton);
    await userEvent.click(detailButton);
    closedDetails.resolve(chengduDetails);
    await userEvent.click(detailButton);
    expect(await screen.findByText("Loading details")).toBeTruthy();
    expect(screen.queryByText("SOCKS password", { exact: true })).toBeNull();
    await userEvent.click(detailButton);

    const sessionDetails = Promise.withResolvers<NodeDetails>();
    vi.mocked(api.nodeDetails).mockReturnValueOnce(sessionDetails.promise);
    await userEvent.click(detailButton);
    await userEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(await screen.findByRole("heading", { name: "Unlock console" })).toBeTruthy();
    sessionDetails.resolve(chengduDetails);
    await waitFor(() => expect(screen.queryByText("SOCKS password", { exact: true })).toBeNull());
    expect(api.lockConsole).toHaveBeenCalled();
  });

  it("marks a timed-out TCP reachability check without raising an alert", async () => {
    const api = await renderAt("/");
    vi.mocked(api.probeNode).mockRejectedValueOnce(new ApiError({ title: "TCP reachability timed out", status: 504, code: "tcp_probe_timeout" }));
    await openGroup("West China");
    expect(screen.getByLabelText("TCP reachability 114 ms, Degraded")).toBeTruthy();

    await userEvent.click(screen.getAllByRole("button", { name: "Check TCP reachability for Chengdu 02" })[0]);

    expect(await screen.findByText("Timeout")).toBeTruthy();
    expect(screen.getByLabelText("TCP reachability Timeout, Unhealthy")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();

    await userEvent.click(screen.getAllByRole("button", { name: "Check TCP reachability for Chengdu 02" })[0]);
    expect(await screen.findByLabelText("TCP reachability 84 ms, Healthy")).toBeTruthy();
    expect(screen.queryByText("Timeout")).toBeNull();
  });

  it("shows an ineligible node instead of mislabeling it as a timeout", async () => {
    const api = await renderAt("/");
    vi.mocked(api.probeNode).mockRejectedValueOnce(new ApiError({ title: "Node unavailable", status: 409, code: "node_ineligible" }));
    await openGroup("West China");
    await userEvent.click(screen.getAllByRole("button", { name: "Check TCP reachability for Chengdu 02" })[0]);
    expect(await screen.findByText("Ineligible")).toBeTruthy();
    expect(screen.getByLabelText("TCP reachability Ineligible, Unhealthy")).toBeTruthy();
  });

  it("prioritizes special groups and sorts China routes and their nodes", async () => {
    await renderAt("/", [
      { ...nodes[0], id: "china-zulu", name: "Zulu 02", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "media", name: "Media 01", group: "音乐/视频APP专线" },
      { ...nodes[1], id: "china-last", name: "Last 01", group: "Zulu ➩ 中国" },
      { ...nodes[0], id: "special", name: "Match 01", group: "2026足球观赛专线" },
      { ...nodes[0], id: "direct", name: "Direct 01", group: "优选直连线路" },
      { ...nodes[1], id: "china-alpha", name: "Alpha 01", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "china-mainland", name: "Mainland 01", group: "港澳台 ➩ 中国大陆" },
    ]);
    const tree = screen.getByRole("tree", { name: "Nodes by group" });
    expect([...tree.children].map((element) => element.getAttribute("aria-label"))).toEqual([
      "2026足球观赛专线 group",
      "优选直连线路 group",
      "音乐/视频APP专线 group",
      "港澳台 ➩ 中国大陆 group",
      "Alpha ➩ 中国 group",
      "Zulu ➩ 中国 group",
    ]);

    const chinaGroup = within(tree).getByRole("treeitem", { name: "Alpha ➩ 中国 group" });
    expect((chinaGroup as HTMLDetailsElement).open).toBe(false);
    await userEvent.click(within(chinaGroup).getByText("Alpha ➩ 中国", { exact: true }));
    expect((chinaGroup as HTMLDetailsElement).open).toBe(true);
    expect(within(chinaGroup).getAllByRole("treeitem").map((element) => element.getAttribute("aria-label"))).toEqual(["Alpha 01", "Zulu 02"]);
    await userEvent.click(within(chinaGroup).getByText("Alpha ➩ 中国", { exact: true }));
    expect((chinaGroup as HTMLDetailsElement).open).toBe(false);
  });

  it("probes sequentially in the same top-down group and node order", async () => {
    const api = await renderAt("/", [
      { ...nodes[0], id: "china-zulu", name: "Zulu 02", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "media", name: "Media 01", group: "音乐/视频APP专线" },
      { ...nodes[1], id: "china-last", name: "Last 01", group: "Zulu ➩ 中国" },
      { ...nodes[0], id: "special", name: "Match 01", group: "2026足球观赛专线" },
      { ...nodes[0], id: "direct", name: "Direct 01", group: "优选直连线路" },
      { ...nodes[1], id: "china-alpha", name: "Alpha 01", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "china-mainland", name: "Mainland 01", group: "港澳台 ➩ 中国大陆" },
    ]);
    const expectedNodeIDs = ["special", "direct", "media", "china-mainland", "china-alpha", "china-zulu", "china-last"];
    const probes = expectedNodeIDs.map(() => Promise.withResolvers<ProbeResult>());
    let probeIndex = 0;
    vi.mocked(api.probeNode).mockImplementation(() => probes[probeIndex++].promise);
    const probeAll = screen.getByRole("button", { name: "Check TCP reachability for all nodes" }) as HTMLButtonElement;

    await userEvent.click(probeAll);

    for (const [index, nodeId] of expectedNodeIDs.entries()) {
      await waitFor(() => expect(api.probeNode).toHaveBeenCalledTimes(index + 1));
      expect(api.probeNode).toHaveBeenNthCalledWith(index + 1, nodeId);
      probes[index].resolve({ nodeId, health: "healthy", tcpLatencyMs: 40 + index, probedAt: "2026-07-15T10:03:00Z" });
    }
    await waitFor(() => expect(probeAll.disabled).toBe(false));
    expect(api.refresh).not.toHaveBeenCalled();
  });

  it("probes only one group's nodes, in node order", async () => {
    const api = await renderAt("/", [
      { ...nodes[0], id: "east-b", name: "Beta 02", group: "East China" },
      { ...nodes[0], id: "east-a", name: "Alpha 01", group: "East China" },
      { ...nodes[1], id: "west", name: "Chengdu 02", group: "West China" },
    ]);
    vi.mocked(api.probeNode).mockImplementation(async (nodeId) => ({ nodeId, health: "healthy", tcpLatencyMs: 30, probedAt: "2026-07-15T10:03:00Z" }));
    const group = screen.getByRole("treeitem", { name: "East China group" });
    const probeGroup = within(group).getByRole("button", { name: "Check TCP reachability for the East China group" }) as HTMLButtonElement;

    await userEvent.click(probeGroup);

    await waitFor(() => expect(probeGroup.disabled).toBe(false));
    expect(vi.mocked(api.probeNode).mock.calls.map(([nodeId]) => nodeId)).toEqual(["east-a", "east-b"]);
  });

  it("labels each node with its upstream protocol", async () => {
    await renderAt("/");
    const group = await openGroup("West China");
    expect(within(group).getByTitle("Upstream protocol: kuaifan-speedin").textContent).toBe("SPEEDIN");
  });
});

describe("subscription URL", () => {
  it("copies the reusable URL from the canonical status page", async () => {
    await renderAt("/subscription");
    await userEvent.click(screen.getByRole("button", { name: "Status" }));
    expect(await screen.findByText(currentConsumerURL)).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Copy subscription link" }));

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(currentConsumerURL);
    expect(await screen.findByText("Link copied.")).toBeTruthy();
  });

  it("falls back to the legacy copy command outside secure contexts", async () => {
    const execCommand = vi.fn().mockReturnValue(true);
    Object.defineProperty(document, "execCommand", { configurable: true, value: execCommand });
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    window.history.replaceState(null, "", "/subscription");
    render(<App api={makeApi(readyStatus())} />);
    await screen.findByText(currentConsumerURL);

    await userEvent.click(screen.getByRole("button", { name: "Copy subscription link" }));

    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(await screen.findByText("Link copied.")).toBeTruthy();
  });
});
