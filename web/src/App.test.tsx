import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { ApiError } from "./api";
import { currentConsumerURL, makeApi, nodes, readyStatus, signedOutStatus } from "./test/fixtures";

const accessToken = "console-token-12345";

async function openAccountLogin() {
  window.history.replaceState(null, "", "/");
  const api = makeApi(signedOutStatus());
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Connect account" });
  await waitFor(() => expect(window.location.pathname).toBe("/signin"));
  return api;
}

async function openTokenSetup() {
  const api = makeApi(signedOutStatus());
  Object.assign(api, { accessStatus: vi.fn().mockResolvedValue({ initialized: false, authenticated: false }) });
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Create console access" });
  expect(window.location.pathname).toBe("/");
  return api;
}

async function openTokenLogin() {
  const api = makeApi(signedOutStatus());
  Object.assign(api, { accessStatus: vi.fn().mockResolvedValue({ initialized: true, authenticated: false }) });
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Unlock console" });
  expect(window.location.pathname).toBe("/");
  return api;
}

describe("access token and browser session", () => {
  it("creates a first-access token after confirmation, trims it, and clears both fields", async () => {
    const api = await openTokenSetup();
    const historyWrites = vi.spyOn(window.history, "replaceState");
    const token = screen.getByLabelText("Access token") as HTMLInputElement;
    const confirmation = screen.getByLabelText("Confirm access token") as HTMLInputElement;

    await userEvent.type(token, `  ${accessToken}  `);
    await userEvent.type(confirmation, `  ${accessToken}  `);
    await userEvent.click(screen.getByRole("button", { name: "Create access" }));

    expect(api.setupAccess).toHaveBeenCalledWith(accessToken);
    expect(token.value).toBe("");
    expect(confirmation.value).toBe("");
    expect(await screen.findByRole("heading", { name: "Connect account" })).toBeTruthy();
    expect(JSON.stringify(historyWrites.mock.calls)).not.toContain(accessToken);
  });

  it("validates token byte guidance and matching confirmation before setup", async () => {
    const api = await openTokenSetup();
    await userEvent.type(screen.getByLabelText("Access token"), "too-short");
    await userEvent.type(screen.getByLabelText("Confirm access token"), "too-short");
    await userEvent.click(screen.getByRole("button", { name: "Create access" }));
    expect(api.setupAccess).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toMatch(/too short or too long/i);

    await userEvent.type(screen.getByLabelText("Access token"), accessToken);
    await userEvent.type(screen.getByLabelText("Confirm access token"), "different-token-12345");
    await userEvent.click(screen.getByRole("button", { name: "Create access" }));
    expect(api.setupAccess).not.toHaveBeenCalled();
    expect(await screen.findByText(/access tokens do not match/i)).toBeTruthy();
  });

  it("submits a returning token and clears it before a blocked request settles", async () => {
    const api = await openTokenLogin();
    const pendingLogin = Promise.withResolvers<void>();
    Object.assign(api, { loginAccess: vi.fn().mockReturnValue(pendingLogin.promise) });
    const token = screen.getByLabelText("Access token") as HTMLInputElement;
    await userEvent.type(token, accessToken);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(api.loginAccess).toHaveBeenCalledWith(accessToken);
    expect(token.value).toBe("");
  });

  it("keeps a rejected returning-token field empty", async () => {
    const api = await openTokenLogin();
    Object.assign(api, { loginAccess: vi.fn().mockRejectedValue(new ApiError({ title: "Rejected", status: 401, code: "invalid_access_token" })) });
    const token = screen.getByLabelText("Access token") as HTMLInputElement;
    await userEvent.type(token, accessToken);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByText("That access token was not accepted.")).toBeTruthy();
    expect(token.value).toBe("");
  });

  it("signs into the existing account at the provider route and clears the account password", async () => {
    const api = await openAccountLogin();
    const historyWrites = vi.spyOn(window.history, "replaceState");
    const password = screen.getByLabelText("Password") as HTMLInputElement;
    await userEvent.selectOptions(screen.getByLabelText("Provider"), "kuaifan");
    await userEvent.type(screen.getByLabelText("Email"), "operator@example.com");
    await userEvent.type(password, "do-not-retain");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await screen.findByRole("heading", { name: "Service status" });
    expect(window.location.pathname).toBe("/");
    expect(password.value).toBe("");
		expect(api.login).toHaveBeenCalledWith("kuaifan", "operator@example.com", "do-not-retain");
    expect(JSON.stringify(historyWrites.mock.calls)).not.toContain("do-not-retain");
  });

  it("shows an invalid account error and clears its password", async () => {
    const api = await openAccountLogin();
    Object.assign(api, { login: vi.fn().mockRejectedValue(new ApiError({ title: "Unauthorized", status: 401, code: "login_rejected" })) });
    await userEvent.selectOptions(screen.getByLabelText("Provider"), "kuaifan");
    const password = screen.getByLabelText("Password") as HTMLInputElement;
    await userEvent.type(screen.getByLabelText("Email"), "operator@example.com");
    await userEvent.type(password, "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("The provider rejected that email or password.")).toBeTruthy();
    expect(password.value).toBe("");
  });

  it("uses only the button spinner while account sign-in is pending", async () => {
    const api = await openAccountLogin();
    const pending = Promise.withResolvers<void>();
    await userEvent.selectOptions(screen.getByLabelText("Provider"), "kuaifan");
    Object.assign(api, { login: vi.fn().mockReturnValue(pending.promise) });
    await userEvent.type(screen.getByLabelText("Email"), "operator@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect((screen.getByRole("button", { name: "Signing in" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText("Signing in to your account…")).toBeNull();
  });


  it("locks the console separately and returns to the canonical route after unlock", async () => {
    window.history.replaceState(null, "", "/signin");
    const api = makeApi(readyStatus());
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });
    expect(window.location.pathname).toBe("/");

    await userEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(await screen.findByRole("heading", { name: "Unlock console" })).toBeTruthy();
    expect(window.location.pathname).toBe("/");
    expect(api.lockConsole).toHaveBeenCalledOnce();
    expect(api.logoutAccount).not.toHaveBeenCalled();

    await userEvent.type(screen.getByLabelText("Access token"), accessToken);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { name: "Service status" })).toBeTruthy();
    expect(window.location.pathname).toBe("/");
  });

  it("moves refresh into the Providers card footer and reloads account and node-list data", async () => {
    const api = makeApi(readyStatus());
    const refreshedNodes = [{ ...nodes[0], name: "Beijing 01" }, nodes[1]];
    vi.mocked(api.nodes)
      .mockResolvedValueOnce({ nodes })
      .mockResolvedValueOnce({ nodes: refreshedNodes });
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });

    const header = screen.getByRole("banner");
    expect(within(header).queryByRole("button", { name: "Refresh account and node list" })).toBeNull();
    expect(within(header).getByRole("button", { name: "Lock console" })).toBeTruthy();
    const providersCard = screen.getByText("Providers", { exact: true }).closest("[data-slot='card']");
    expect(providersCard).not.toBeNull();
    const refreshButton = within(providersCard as HTMLElement).getByRole("button", { name: "Refresh all" });
    expect(refreshButton.querySelector(".lucide-refresh-cw")).toBeTruthy();
    expect(within(providersCard as HTMLElement).getByRole("button", { name: "Sign out all" })).toBeTruthy();

    await userEvent.click(refreshButton);

    await waitFor(() => expect(api.refresh).toHaveBeenCalledOnce());
    expect(api.refresh).toHaveBeenCalledWith("");
    await waitFor(() => expect(api.status).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(api.nodes).toHaveBeenCalledTimes(2));
    await userEvent.click(screen.getByRole("button", { name: "KuaiFan" }));
    await userEvent.click(within(screen.getByLabelText("East China group")).getByText("East China", { exact: true }));
    expect(await screen.findByRole("treeitem", { name: "Beijing 01" })).toBeTruthy();
    expect(screen.queryByText(/(?:account|nodes) (?:refreshed|updated)/i)).toBeNull();
  });

  it("renders every logical catalog row supplied by the backend", async () => {
    const music = Array.from({ length: 5 }, (_, index) => ({
      ...nodes[0],
      id: `music-${index + 1}`,
      name: `音乐/视频专线 · ${index + 1}`,
      group: "音乐/视频APP专线",
    }));
    const catalogNodes: typeof nodes = [
      ...music,
      { ...nodes[0], id: "australia-2", name: "澳大利亚 ➩ 中国 · 2", group: "澳洲 ➩ 中国" },
      { ...nodes[0], id: "australia-7", name: "澳大利亚 ➩ 中国 · 7", group: "澳洲 ➩ 中国" },
    ];
    const status = readyStatus();
    status.nodes = { total: catalogNodes.length, eligible: catalogNodes.length, healthy: catalogNodes.length };
    status.subscription.nodeCount = catalogNodes.length;
    render(<App api={makeApi(status, catalogNodes)} />);
    await userEvent.click(await screen.findByRole("button", { name: "KuaiFan" }));

    expect(await screen.findByText("7 available")).toBeTruthy();
    const musicGroup = screen.getByLabelText("音乐/视频APP专线 group");
    expect(musicGroup.textContent).toContain("5");
    await userEvent.click(within(musicGroup).getByText("音乐/视频APP专线", { exact: true }));
    for (const node of music) expect(screen.getByRole("treeitem", { name: node.name })).toBeTruthy();

    const australiaGroup = screen.getByLabelText("澳洲 ➩ 中国 group");
    expect(australiaGroup.textContent).toContain("2");
    await userEvent.click(within(australiaGroup).getByText("澳洲 ➩ 中国", { exact: true }));
    expect(screen.getByRole("treeitem", { name: "澳大利亚 ➩ 中国 · 2" })).toBeTruthy();
    expect(screen.getByRole("treeitem", { name: "澳大利亚 ➩ 中国 · 7" })).toBeTruthy();
  });

  it("requires an explicit provider before account sign-in", async () => {
    const api = await openAccountLogin();
    await userEvent.type(screen.getByLabelText("Email"), "operator@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Choose a provider before entering account credentials.");
    expect(api.login).not.toHaveBeenCalled();
  });

  it("switches provider screens and adds a disconnected provider account", async () => {
    const api = makeApi(readyStatus());
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });
    await userEvent.click(screen.getByRole("button", { name: "QuickFox" }));
    expect(screen.getByText("Connect QuickFox", { selector: "[data-slot='card-title']" })).toBeTruthy();
    expect(screen.queryByRole("tree", { name: "Nodes by group" })).toBeNull();
    await userEvent.type(screen.getByLabelText("Email"), "quickfox@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "quickfox-secret");
    await userEvent.click(screen.getByRole("button", { name: "Connect QuickFox" }));
    await waitFor(() => expect(api.login).toHaveBeenCalledWith("quickfox", "quickfox@example.com", "quickfox-secret"));
  });

  it("scopes Providers footer actions to the Status tab", async () => {
    render(<App api={makeApi(readyStatus())} />);
    await screen.findByRole("heading", { name: "Service status" });

    const views = screen.getByRole("navigation", { name: "Console views" });
    expect(within(views).getByRole("button", { name: "Status" })).toBeTruthy();
    expect(within(views).queryByRole("button", { name: "All providers" })).toBeNull();
    expect(screen.getByText("Providers", { exact: true })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Refresh all" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign out all" })).toBeTruthy();
    expect(screen.getByText("Service", { exact: true })).toBeTruthy();
    expect(screen.getByText("Subscription link", { exact: true })).toBeTruthy();
    expect(screen.queryByRole("tree", { name: "Nodes by group" })).toBeNull();

    await userEvent.click(within(views).getByRole("button", { name: "KuaiFan" }));
    expect(screen.getByText("KuaiFan account", { selector: "[data-slot='card-title']" })).toBeTruthy();
    expect(screen.queryByText("Providers", { exact: true })).toBeNull();
    expect(screen.queryByRole("button", { name: "Refresh all" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Sign out all" })).toBeNull();
    expect(screen.queryByText("Service", { exact: true })).toBeNull();
    expect(screen.queryByText("Subscription link", { exact: true })).toBeNull();
    expect(await screen.findByRole("tree", { name: "Nodes by group" })).toBeTruthy();

    await userEvent.click(within(views).getByRole("button", { name: "Status" }));
    expect(screen.getByText("Providers", { exact: true })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Refresh all" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign out all" })).toBeTruthy();
    expect(screen.getByText("Service", { exact: true })).toBeTruthy();
    expect(screen.getByText("Subscription link", { exact: true })).toBeTruthy();
    expect(screen.queryByRole("tree", { name: "Nodes by group" })).toBeNull();
  });

  it("renders status panels while the subscription link is still loading", async () => {
    const api = makeApi(readyStatus());
    const pendingSubscription = Promise.withResolvers<{ url: string }>();
    Object.assign(api, { subscriptionURL: vi.fn().mockReturnValue(pendingSubscription.promise) });
    render(<App api={api} />);

    expect(await screen.findByText("Service", { exact: true })).toBeTruthy();
    expect(screen.getByText("Subscription link", { exact: true })).toBeTruthy();
    expect(screen.getByText("Loading link…")).toBeTruthy();

    pendingSubscription.resolve({ url: currentConsumerURL });
    expect(await screen.findByText(currentConsumerURL)).toBeTruthy();
  });

  it("shows the provider-specific tier and active subscription duration", async () => {
    const status = readyStatus();
    status.accounts = {
      ...status.accounts,
      kuaifan: {
        ...status.accounts!.kuaifan,
        subscriptionEndsAt: new Date(Date.now() + 23 * 24 * 60 * 60 * 1000).toISOString(),
      },
    };
    render(<App api={makeApi(status)} />);
    await screen.findByRole("heading", { name: "Service status" });
    await userEvent.click(screen.getByRole("button", { name: "KuaiFan" }));
    expect(screen.getByText("Subscription tier")).toBeTruthy();
    expect(screen.getByText("VIP", { exact: true }).closest("[data-slot='badge']")).toBeNull();
    expect(screen.getByText("Subscription", { exact: true })).toBeTruthy();
    expect(screen.getByText("Active · Valid for 23 days", { exact: true })).toBeTruthy();
    expect(screen.getByText(/^Ends /)).toBeTruthy();
    expect(screen.queryByText("Access")).toBeNull();
    expect(screen.queryByText("Valid until")).toBeNull();
  });

  it.each([
    ["free subscriptions", false, undefined, "Free"],
    ["subscriptions without an end date", true, undefined, "Active · End date unavailable"],
    ["short-lived subscriptions", true, new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(), "Active · Valid for 2 hours"],
    ["expired subscriptions", true, new Date(Date.now() - 60 * 60 * 1000).toISOString(), "Expired"],
  ])("handles %s", async (_case, subscriptionActive, subscriptionEndsAt, expected) => {
    const status = readyStatus();
    status.accounts = {
      ...status.accounts,
      quickfox: { provider: "quickfox", display: "q•••@example.com", tier: "Standard", subscriptionActive, subscriptionEndsAt },
    };
    render(<App api={makeApi(status)} />);
    await screen.findByRole("heading", { name: "Service status" });
    await userEvent.click(screen.getByRole("button", { name: "QuickFox" }));
    expect(screen.getByText("Standard", { exact: true })).toBeTruthy();
    expect(screen.getByText(expected, { exact: true })).toBeTruthy();
    expect(screen.queryByText("Valid until")).toBeNull();
  });

  it("defensively hides ineligible nodes returned by the backend", async () => {
    const inventory = [...nodes, { ...nodes[0], id: "blocked", name: "Paid-only archive", eligible: false }];
    render(<App api={makeApi(readyStatus(), inventory)} />);
    await screen.findByRole("heading", { name: "Service status" });
    expect(screen.queryByRole("treeitem", { name: "Paid-only archive" })).toBeNull();
    expect(screen.queryByText("Paid-only archive")).toBeNull();
  });

  it("refreshes and removes one provider account without locking the console", async () => {
    const api = makeApi(readyStatus());
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });
    await userEvent.click(screen.getByRole("button", { name: "KuaiFan" }));
    expect(screen.queryByRole("button", { name: "Connect KuaiFan" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Refresh provider" }));
    await waitFor(() => expect(api.refresh).toHaveBeenCalledWith("kuaifan"));
    await userEvent.click(screen.getByRole("button", { name: "Remove account" }));
    await userEvent.click(screen.getByRole("button", { name: "Confirm removal" }));
    await waitFor(() => expect(api.logoutAccount).toHaveBeenCalledWith("kuaifan"));
    expect(api.lockConsole).not.toHaveBeenCalled();
  });

  it("signs out every linked provider in order without locking the console", async () => {
    const status = readyStatus();
    status.accounts = {
      ...status.accounts,
      quickfox: { provider: "quickfox", display: "q•••@example.com", tier: "Standard", subscriptionActive: true },
    };
    const api = makeApi(status);
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });

    await userEvent.click(screen.getByRole("button", { name: "Sign out all" }));

    await waitFor(() => expect(api.logoutAccount).toHaveBeenCalledTimes(2));
    expect(api.logoutAccount).toHaveBeenNthCalledWith(1, "kuaifan");
    expect(api.logoutAccount).toHaveBeenNthCalledWith(2, "quickfox");
    expect(vi.mocked(api.logoutAccount).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(api.logoutAccount).mock.invocationCallOrder[1]);
    expect(api.lockConsole).not.toHaveBeenCalled();
    await waitFor(() => expect(api.status).toHaveBeenCalledTimes(2));
    expect(api.nodes).toHaveBeenCalledTimes(2);
    expect(api.subscriptionURL).toHaveBeenCalledTimes(2);
  });

  it("disables Sign out all with no linked accounts and while refreshing", async () => {
    const emptyStatus = readyStatus();
    emptyStatus.accounts = {};
    const emptyApi = makeApi(emptyStatus);
    render(<App api={emptyApi} />);
    await screen.findByRole("heading", { name: "Service status" });
    expect((screen.getByRole("button", { name: "Sign out all" }) as HTMLButtonElement).disabled).toBe(true);

    const pendingRefresh = Promise.withResolvers<void>();
    const api = makeApi(readyStatus());
    Object.assign(api, { refresh: vi.fn().mockReturnValue(pendingRefresh.promise) });
    render(<App api={api} />);
    const consoles = await screen.findAllByRole("heading", { name: "Service status" });
    const currentConsole = consoles[consoles.length - 1].closest("main") as HTMLElement;
    await userEvent.click(within(currentConsole).getByRole("button", { name: "Refresh all" }));
    expect((within(currentConsole).getByRole("button", { name: "Sign out all" }) as HTMLButtonElement).disabled).toBe(true);
    pendingRefresh.resolve();
  });

  it("builds provider, group, and name filtered subscription URLs while defaulting to all", async () => {
    const status = readyStatus();
    status.accounts = {
      ...status.accounts,
      quickfox: { provider: "quickfox", display: "q•••@example.com", tier: "VIP", subscriptionActive: true, subscriptionEndsAt: "2026-10-27T14:34:52Z" },
    };
    const mixedNodes = [
      ...nodes,
      { ...nodes[0], id: "qf-sea", provider: "quickfox", name: "Seattle Edge", group: "Domestic / US" },
      { ...nodes[0], id: "qf-la", provider: "quickfox", name: "Los Angeles Home", group: "Domestic / US" },
    ];
    render(<App api={makeApi(status, mixedNodes)} />);
    expect(await screen.findByText(currentConsumerURL)).toBeTruthy();
    await userEvent.selectOptions(screen.getByLabelText("Provider"), "quickfox");
    await userEvent.selectOptions(screen.getByLabelText("Group"), "Domestic / US");
    await userEvent.type(screen.getByLabelText("Node name"), "Edge");
    const filtered = await screen.findByText((content) => content.includes("provider=quickfox") && content.includes("group=Domestic") && content.includes("name=Edge"));
    const parsed = new URL(filtered.textContent || "");
    expect(parsed.searchParams.get("provider")).toBe("quickfox");
    expect(parsed.searchParams.get("group")).toBe("Domestic / US");
    expect(parsed.searchParams.get("name")).toBe("Edge");
    await userEvent.selectOptions(screen.getByLabelText("Provider"), "");
    await userEvent.selectOptions(screen.getByLabelText("Group"), "");
    await userEvent.clear(screen.getByLabelText("Node name"));
    expect(await screen.findByText(currentConsumerURL)).toBeTruthy();
  });

  it.each([
    ["authenticating", "Authenticating"],
    ["syncing", "Syncing"],
    ["ready", "Ready"],
    ["degraded", "Needs attention"],
    ["error", "Service error"],
  ] as const)("renders the %s service state with text, not color alone", async (state, expected) => {
    const api = makeApi({ ...readyStatus(), state });
    render(<App api={api} />);
    expect((await screen.findAllByText(expected, { exact: true })).length).toBeGreaterThan(0);
  });

  it("omits redundant ready-state and connection-counter status", async () => {
    render(<App api={makeApi(readyStatus())} />);
    await screen.findByRole("heading", { name: "Service status" });
    expect(screen.queryByText("Service is ready.", { exact: true })).toBeNull();
    expect(screen.queryByText("Legacy tunnel", { exact: true })).toBeNull();
    expect(screen.queryByText("Connections", { exact: true })).toBeNull();
  });

  it("avoids browser storage while rendering the status console", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const api = makeApi(readyStatus());
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });
    await waitFor(() => expect(api.accessStatus).toHaveBeenCalled());
    expect(setItem).not.toHaveBeenCalled();
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("");
  });
});
