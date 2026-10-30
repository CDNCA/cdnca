import { useMemo, useState } from "react";
import {
  Alert,
  Button,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  Input,
  type TableColumnsType,
} from "antd";
import { Send } from "lucide-react";
import { useTranslation } from "react-i18next";

import {
  sitesApi,
  type BatchSiteActionItemResult,
  type BatchSiteProtocols,
} from "../../api/sites";
import { useSessionStore } from "../../auth/session";
import { DataState } from "../../components/DataState";
import "./i18n";
import { FeedbackWhen } from "@cdnca/ui";

// 网站协议批量设置：直接批量写所选网站自己的
// http2_enabled / http3_enabled / tls_prefer_server_ciphers，经
// POST /v1/sites/batch-action（action=set_protocols），逐站校验版本、
// 写审计并触发重新发布。只有输入的网站会被改动。

const uuidPattern =
  /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const maxSites = 100;

type Toggle = "keep" | "on" | "off";
type Prefer = Toggle | "preset";

export interface SiteProtocolsClient {
  list: typeof sitesApi.list;
  batchAction: typeof sitesApi.batchAction;
}

interface ResultRow {
  id: string;
  domain: string;
  result: BatchSiteActionItemResult;
}

function siteSelection(value: string): string[] | null {
  const items = value
    .split(/[\s,]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (
    items.length < 1 ||
    items.length > maxSites ||
    items.some((item) => !uuidPattern.test(item)) ||
    new Set(items).size !== items.length
  ) {
    return null;
  }
  return items;
}

function protocolChanges(
  http2: Toggle,
  http3: Toggle,
  prefer: Prefer,
): BatchSiteProtocols | null {
  const protocols: BatchSiteProtocols = {};
  if (http2 !== "keep") protocols.http2_enabled = http2 === "on";
  if (http3 !== "keep") protocols.http3_enabled = http3 === "on";
  if (prefer === "preset") protocols.tls_prefer_server_ciphers = null;
  else if (prefer !== "keep")
    protocols.tls_prefer_server_ciphers = prefer === "on";
  return Object.keys(protocols).length > 0 ? protocols : null;
}

export default function SiteProtocolBatchPage({
  client = sitesApi,
}: {
  client?: SiteProtocolsClient;
}) {
  const { t } = useTranslation("siteProtocols");
  const { accessToken, principal } = useSessionStore();
  const allowed = Boolean(
    accessToken && principal?.permissions.includes("sites.manage"),
  );
  const [siteIDs, setSiteIDs] = useState("");
  const [http2, setHTTP2] = useState<Toggle>("keep");
  const [http3, setHTTP3] = useState<Toggle>("keep");
  const [prefer, setPrefer] = useState<Prefer>("keep");
  const [formError, setFormError] = useState<"sites" | "changes" | null>(null);
  const [requestError, setRequestError] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [rows, setRows] = useState<ResultRow[]>();

  const toggleOptions = useMemo(
    () => [
      { value: "keep", label: t("keep") },
      { value: "on", label: t("on") },
      { value: "off", label: t("off") },
    ],
    [t],
  );
  const preferOptions = useMemo(
    () => [...toggleOptions, { value: "preset", label: t("preset") }],
    [t, toggleOptions],
  );

  const columns = useMemo<TableColumnsType<ResultRow>>(
    () => [
      { title: t("columns.site"), dataIndex: "domain", key: "site", ellipsis: true },
      {
        title: t("columns.state"),
        key: "state",
        width: 120,
        render: (_, row) =>
          row.result.status === "failed" ? (
            <Tag color="red">{t("itemStates.failed")}</Tag>
          ) : (
            <Tag color="green">{t("itemStates.updated")}</Tag>
          ),
      },
      {
        title: t("columns.error"),
        key: "error",
        width: 240,
        render: (_, row) =>
          row.result.status === "failed"
            ? t(`errors.${row.result.error.code}`, {
                defaultValue: t("errors.unknown"),
              })
            : "-",
      },
    ],
    [t],
  );

  if (!allowed || !accessToken || !principal) {
    return <DataState status="forbidden" message={t("forbidden")} />;
  }

  const submit = async () => {
    const selected = siteSelection(siteIDs);
    if (!selected) {
      setFormError("sites");
      return;
    }
    const protocols = protocolChanges(http2, http3, prefer);
    if (!protocols) {
      setFormError("changes");
      return;
    }
    setFormError(null);
    setRequestError(false);
    setSubmitting(true);
    try {
      // the current version of each selected site: a site changed since is
      // reported per site (version_conflict), never overwritten
      const listed = await client.list(accessToken, {
        page: 1,
        limit: maxSites,
        site_ids: selected.join(","),
      });
      const byID = new Map(listed.items.map((item) => [item.id, item]));
      const missing: ResultRow[] = [];
      const items: Array<{ id: string; expected_version: number }> = [];
      for (const id of selected) {
        const site = byID.get(id);
        if (site) items.push({ id, expected_version: site.version });
        else
          missing.push({
            id,
            domain: id,
            result: { id, status: "failed", error: { code: "site_not_found" } },
          });
      }
      let results: ResultRow[] = [];
      if (items.length > 0) {
        const response = await client.batchAction(
          accessToken,
          { action: "set_protocols", items, protocols },
          `site-protocols-${crypto.randomUUID()}`,
        );
        results = response.items.map((result) => ({
          id: result.id,
          domain: byID.get(result.id)?.domain ?? result.id,
          result,
        }));
      }
      const order = new Map(selected.map((id, index) => [id, index]));
      setRows(
        [...results, ...missing].sort(
          (left, right) => (order.get(left.id) ?? 0) - (order.get(right.id) ?? 0),
        ),
      );
    } catch {
      setRequestError(true);
    } finally {
      setSubmitting(false);
    }
  };

  const failed = rows?.filter((row) => row.result.status === "failed").length ?? 0;

  return (
    <section aria-labelledby="site-protocol-title">
      <Typography.Title id="site-protocol-title" level={4}>
        {t("title")}
      </Typography.Title>
      <Space direction="vertical" size={12} style={{ width: "100%" }}>
        <label>
          <span>{t("siteIDs")}</span>
          <Input.TextArea
            aria-label={t("siteIDs")}
            value={siteIDs}
            onChange={(event) => setSiteIDs(event.target.value)}
            placeholder={t("siteIDsPlaceholder")}
            autoSize={{ minRows: 3, maxRows: 8 }}
            status={formError === "sites" ? "error" : undefined}
          />
        </label>
        <Space wrap size={16}>
          <label>
            <span>{t("http2")} </span>
            <Select<Toggle>
              aria-label={t("http2")}
              value={http2}
              onChange={setHTTP2}
              options={toggleOptions}
              style={{ width: 120 }}
            />
          </label>
          <label>
            <span>{t("http3")} </span>
            <Select<Toggle>
              aria-label={t("http3")}
              value={http3}
              onChange={setHTTP3}
              options={toggleOptions}
              style={{ width: 120 }}
            />
          </label>
          <label>
            <span>{t("prefer")} </span>
            <Select<Prefer>
              aria-label={t("prefer")}
              value={prefer}
              onChange={setPrefer}
              options={preferOptions}
              style={{ width: 140 }}
            />
          </label>
        </Space>
        <Typography.Text type="secondary">{t("http3Hint")}</Typography.Text>
        {formError ? (
          <FeedbackWhen
            title={formError === "sites" ? t("invalidSites") : t("noChanges")}
          />
        ) : null}
        {requestError ? <FeedbackWhen title={t("requestFailed")} /> : null}
        <Space wrap>
          <Button
            type="primary"
            icon={<Send size={16} />}
            loading={submitting}
            onClick={() => void submit()}
          >
            {t("submit")}
          </Button>
        </Space>
        {rows ? (
          <>
            <Alert
              type={failed === 0 ? "success" : failed === rows.length ? "error" : "warning"}
              showIcon
              message={t("summary", { updated: rows.length - failed, failed })}
            />
            <Table<ResultRow>
              rowKey="id"
              size="small"
              pagination={false}
              columns={columns}
              dataSource={rows}
              scroll={{ x: 600 }}
            />
          </>
        ) : null}
      </Space>
    </section>
  );
}
