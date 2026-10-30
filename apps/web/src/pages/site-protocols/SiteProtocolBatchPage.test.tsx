import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Principal } from "../../api/auth";
import type { SiteListItem, SiteListResponse } from "../../api/sites";
import { useSessionStore } from "../../auth/session";
import i18n from "../../i18n";
import { authResponse, principal } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import SiteProtocolBatchPage, {
  type SiteProtocolsClient,
} from "./SiteProtocolBatchPage";

const siteA = "22222222-2222-4222-8222-222222222222";
const siteB = "44444444-4444-4444-8444-444444444444";
const siteMissing = "55555555-5555-4555-8555-555555555555";

function listed(id: string, domain: string, version: number): SiteListItem {
  return { id, domain, version } as SiteListItem;
}

function adminPrincipal(overrides: Partial<Principal> = {}) {
  return principal({
    scope_kind: "platform",
    tenant_id: null,
    permissions: ["sites.read", "sites.manage"],
    ...overrides,
  });
}

function setSession(actor = adminPrincipal()) {
  useSessionStore
    .getState()
    .setSession({ ...authResponse(actor), access_token: "token" }, actor, "new");
}

function client(overrides: Partial<SiteProtocolsClient> = {}): SiteProtocolsClient {
  const list: SiteListResponse = {
    items: [listed(siteA, "a.example.com", 3), listed(siteB, "b.example.com", 7)],
    total: 2,
    page: 1,
    limit: 100,
  };
  return {
    list: vi.fn().mockResolvedValue(list),
    batchAction: vi.fn().mockResolvedValue({
      items: [
        { id: siteA, status: "updated", site: { id: siteA } },
        { id: siteB, status: "failed", error: { code: "version_conflict" } },
      ],
    }),
    ...overrides,
  };
}

async function choose(label: string, option: string) {
  const user = userEvent.setup();
  await user.click(screen.getByRole("combobox", { name: label }));
  const listbox = await screen.findAllByTitle(option);
  await user.click(listbox[listbox.length - 1]);
}

afterEach(async () => {
  useSessionStore.getState().clearSession();
  vi.restoreAllMocks();
  await act(async () => {
    await i18n.changeLanguage("zh-CN");
  });
});

describe("SiteProtocolBatchPage", () => {
  it("fails closed without sites.manage", async () => {
    setSession(adminPrincipal({ permissions: ["sites.read"] }));
    const api = client();
    renderWithProviders(<SiteProtocolBatchPage client={api} />);
    expect(await screen.findByText("无权管理网站")).toBeInTheDocument();
    expect(api.list).not.toHaveBeenCalled();
  });

  it("writes only the chosen columns of the listed sites at their current versions", async () => {
    setSession();
    const api = client();
    const user = userEvent.setup();
    renderWithProviders(<SiteProtocolBatchPage client={api} />);

    await user.type(screen.getByLabelText("网站 ID"), `${siteA}\n${siteB}\n${siteMissing}`);
    await choose("HTTP/2", "关闭");
    await choose("优先使用服务端套件", "按预设");
    await user.click(screen.getByRole("button", { name: "批量保存" }));

    await waitFor(() => expect(api.batchAction).toHaveBeenCalledOnce());
    expect(api.list).toHaveBeenCalledWith("token", {
      page: 1,
      limit: 100,
      site_ids: `${siteA},${siteB},${siteMissing}`,
    });
    const [, input, key] = vi.mocked(api.batchAction).mock.calls[0];
    // HTTP/3 left at "不修改" is omitted; the missing site is never sent
    expect(input).toEqual({
      action: "set_protocols",
      items: [
        { id: siteA, expected_version: 3 },
        { id: siteB, expected_version: 7 },
      ],
      protocols: { http2_enabled: false, tls_prefer_server_ciphers: null },
    });
    expect(key).toMatch(/^site-protocols-/);

    expect(await screen.findByText("已保存 1 个网站，失败 2 个")).toBeInTheDocument();
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText("a.example.com")).toBeInTheDocument();
    expect(within(rows[0]).getByText("已保存")).toBeInTheDocument();
    expect(within(rows[1]).getByText("网站刚被其他操作修改，请重新提交")).toBeInTheDocument();
    expect(within(rows[2]).getByText(siteMissing)).toBeInTheDocument();
    expect(within(rows[2]).getByText("网站不存在或无权访问")).toBeInTheDocument();
  });

  it("requires at least one change and valid IDs before any request", async () => {
    setSession();
    const api = client();
    const user = userEvent.setup();
    renderWithProviders(<SiteProtocolBatchPage client={api} />);

    await user.type(screen.getByLabelText("网站 ID"), "NOT-A-UUID");
    await user.click(screen.getByRole("button", { name: "批量保存" }));
    const invalid = (await screen.findByText("请输入有效且不重复的网站 ID（最多 100 个）")).closest(
      ".cdnca-feedback",
    ) as HTMLElement;
    await user.click(within(invalid).getByRole("button", { name: "知道了" }));

    await user.clear(screen.getByLabelText("网站 ID"));
    await user.type(screen.getByLabelText("网站 ID"), siteA);
    await user.click(screen.getByRole("button", { name: "批量保存" }));
    expect(await screen.findByText("请至少选择一项要修改的设置")).toBeInTheDocument();
    expect(api.list).not.toHaveBeenCalled();
    expect(api.batchAction).not.toHaveBeenCalled();
  });

  it("never renders raw server errors", async () => {
    setSession();
    const api = client({ batchAction: vi.fn().mockRejectedValue(new Error("private database detail")) });
    const user = userEvent.setup();
    renderWithProviders(<SiteProtocolBatchPage client={api} />);

    await user.type(screen.getByLabelText("网站 ID"), siteA);
    await choose("HTTP/3", "开启");
    await user.click(screen.getByRole("button", { name: "批量保存" }));
    expect(await screen.findByText("批量保存失败，请稍后重试")).toBeInTheDocument();
    expect(screen.queryByText("private database detail")).not.toBeInTheDocument();
  });
});
