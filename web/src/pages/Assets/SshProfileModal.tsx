import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Checkbox, Input, InputNumber, message, Modal, Radio, Select, Space, Typography } from 'antd';
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useCollection } from '../../api/hooks';
import { Mono } from '../../components/Semantic';
import { Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import { buildSshConfig, keyscanCommands, validateSshConfig, type SshApp, type SshAuth, type SshTargetDraft } from './sshProfile';
import type { Asset } from '../../types';

const { Text, Paragraph } = Typography;

const newTarget = (asset: Asset, shared: Pick<SshTargetDraft, 'user' | 'auth' | 'privateKeyFile'>): SshTargetDraft => ({
  ip: asset.address,
  sshPort: 22,
  user: shared.user,
  auth: shared.auth,
  privateKeyFile: shared.privateKeyFile,
  apps: [],
});

// Generates the Worker-local ssh-config.json for the selected hosts. Nothing
// here is sent to the Server: SSH settings live only on the Worker, which
// rejects passwords and only reads key files already on its own disk.
export const SshProfileModal: React.FC<{ open: boolean; initialAssetIds: string[]; onClose: () => void }> = ({ open, initialAssetIds, onClose }) => {
  const { palette } = useAppTheme();
  const { data: assets, loading } = useCollection('assets', '', open);
  const hosts = useMemo(() => assets.filter(asset => asset.kind === 'host'), [assets]);
  const [selected, setSelected] = useState<string[]>([]);
  const [knownHostsFile, setKnownHostsFile] = useState('known_hosts');
  const [shared, setShared] = useState<Pick<SshTargetDraft, 'user' | 'auth' | 'privateKeyFile'>>({ user: 'scanner_ro', auth: 'agent', privateKeyFile: 'keys/scan_ed25519' });
  const [targets, setTargets] = useState<Record<string, SshTargetDraft>>({});

  // Each opening starts from the asset it was opened from; drafts are not kept.
  const initialKey = initialAssetIds.join(',');
  useEffect(() => {
    if (!open) return;
    setSelected(initialKey ? initialKey.split(',') : []);
    setTargets({});
  }, [open, initialKey]);

  const chosen = hosts.filter(asset => selected.includes(asset.id));
  const drafts = chosen.map(asset => targets[asset.id] ?? newTarget(asset, shared));
  const config = { knownHostsFile, targets: drafts };
  const problems = drafts.length ? validateSshConfig(config) : [];
  const text = buildSshConfig(config);

  const update = (asset: Asset, patch: Partial<SshTargetDraft>) =>
    setTargets(current => ({ ...current, [asset.id]: { ...(current[asset.id] ?? newTarget(asset, shared)), ...patch } }));
  const updateApp = (asset: Asset, index: number, patch: Partial<SshApp>) => {
    const apps = [...(targets[asset.id]?.apps ?? [])];
    apps[index] = { ...apps[index], ...patch };
    update(asset, { apps });
  };
  // Shared values apply to every selected host, replacing per-host edits of the same fields.
  const applyShared = (patch: Partial<typeof shared>) => {
    const next = { ...shared, ...patch };
    setShared(next);
    setTargets(current => Object.fromEntries(Object.entries(current).map(([id, draft]) => [id, { ...draft, ...patch }])));
  };
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); message.success('已复制配置，请粘贴到 Worker 上的 ssh-config.json'); }
    catch { message.error('浏览器不允许复制，请改用下载'); }
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url; anchor.download = 'ssh-config.json';
    document.body.appendChild(anchor); anchor.click(); anchor.remove();
    URL.revokeObjectURL(url);
  };
  const ready = drafts.length > 0 && problems.length === 0;
  const muted = { color: palette.textSecondary };
  const box = { margin: 0, padding: 12, maxHeight: 260, overflow: 'auto', background: palette.bgSubtle, border: `1px solid ${palette.borderSubtle}`, borderRadius: 8, fontSize: 12, whiteSpace: 'pre' as const };

  return (
    <Modal title="SSH 采集配置" open={open} onCancel={onClose} width="min(1080px, 100vw)" destroyOnClose
      footer={<Space wrap><Button onClick={onClose}>关闭</Button><Button disabled={!ready} onClick={() => void copy()}>复制配置</Button><Button type="primary" disabled={!ready} onClick={download}>下载 ssh-config.json</Button></Space>}>
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Alert type="info" showIcon message="配置只在浏览器中生成，不会上传到平台"
          description="Linux 软件包采集由 Worker 通过 SSH 公钥认证完成。平台不保存、也不接收密钥或密码；这里只填写 Worker 本机上已有私钥文件的路径。下载的文件放到 Worker 上，用 sec-worker --ssh-config 启动后生效。" />

        <Panel title="选择主机">
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Select aria-label="选择主机" mode="multiple" style={{ width: '100%' }} loading={loading} value={selected} onChange={setSelected}
              placeholder="选择已登记主机（只支持数字 IP）" optionFilterProp="label" maxTagCount="responsive"
              options={hosts.map(asset => ({ value: asset.id, label: `${asset.address} · ${asset.name || asset.businessGroup}` }))} />
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}><span style={muted}>known_hosts 文件</span>
                <Input aria-label="known_hosts 文件" value={knownHostsFile} onChange={event => setKnownHostsFile(event.target.value)} placeholder="known_hosts" /></label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}><span style={muted}>只读账号（应用到全部）</span>
                <Input aria-label="统一只读账号" value={shared.user} onChange={event => applyShared({ user: event.target.value.trim() })} /></label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}><span style={muted}>认证方式（应用到全部）</span>
                <Radio.Group aria-label="统一认证方式" value={shared.auth} onChange={event => applyShared({ auth: event.target.value as SshAuth })} optionType="button"
                  options={[{ value: 'agent', label: 'SSH Agent' }, { value: 'private-key', label: '私钥文件' }]} /></div>
              {shared.auth === 'private-key' && <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}><span style={muted}>Worker 上的私钥路径（应用到全部）</span>
                <Input aria-label="统一私钥路径" value={shared.privateKeyFile} onChange={event => applyShared({ privateKeyFile: event.target.value.trim() })} /></label>}
            </div>
            <Text style={muted}>相对路径以 ssh-config.json 所在目录为基准。私钥须只有 Worker 运行账号可读；加密私钥请先加入 SSH Agent 再选 SSH Agent。</Text>
          </Space>
        </Panel>

        {chosen.map(asset => {
          const draft = targets[asset.id] ?? newTarget(asset, shared);
          return (
            <Panel key={asset.id} title={<Mono>{asset.address}</Mono>} extra={<span style={muted}>{asset.name || asset.businessGroup}</span>}>
              <Space direction="vertical" size={12} style={{ width: '100%' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '120px minmax(160px, 1fr) auto minmax(200px, 1.4fr)', gap: 12, alignItems: 'center' }}>
                  <InputNumber aria-label={`${asset.address} SSH 端口`} min={1} max={65535} value={draft.sshPort} onChange={value => update(asset, { sshPort: Number(value ?? 0) })} addonBefore="端口" style={{ width: '100%' }} />
                  <Input aria-label={`${asset.address} 只读账号`} value={draft.user} onChange={event => update(asset, { user: event.target.value.trim() })} addonBefore="账号" />
                  <Radio.Group aria-label={`${asset.address} 认证方式`} value={draft.auth} onChange={event => update(asset, { auth: event.target.value as SshAuth })} optionType="button"
                    options={[{ value: 'agent', label: 'Agent' }, { value: 'private-key', label: '私钥' }]} />
                  {draft.auth === 'private-key' ? <Input aria-label={`${asset.address} 私钥路径`} value={draft.privateKeyFile} onChange={event => update(asset, { privateKeyFile: event.target.value.trim() })} addonBefore="私钥路径" />
                    : <Text style={muted}>使用 Worker 当前用户的 SSH Agent</Text>}
                </div>
                <div>
                  <Text strong>Java / Go 应用部署目录（可选，最多 8 个）</Text>
                  {(draft.apps ?? []).map((app, index) => (
                    <div key={index} style={{ display: 'grid', gridTemplateColumns: '160px minmax(220px, 1fr) auto auto', gap: 8, alignItems: 'center', marginTop: 8 }}>
                      <Input aria-label={`${asset.address} 应用 ${index + 1} 别名`} value={app.alias} placeholder="别名，如 orders" onChange={event => updateApp(asset, index, { alias: event.target.value.trim() })} />
                      <Input aria-label={`${asset.address} 应用 ${index + 1} 目录`} value={app.directory} placeholder="/opt/example-orders" onChange={event => updateApp(asset, index, { directory: event.target.value.trim() })} />
                      <Space size={4}><Checkbox checked={app.includeJava} onChange={event => updateApp(asset, index, { includeJava: event.target.checked })}>Java</Checkbox><Checkbox checked={app.includeGo} onChange={event => updateApp(asset, index, { includeGo: event.target.checked })}>Go</Checkbox></Space>
                      <Button aria-label={`删除应用 ${app.alias || index + 1}`} type="text" icon={<DeleteOutlined />} onClick={() => update(asset, { apps: (draft.apps ?? []).filter((_, i) => i !== index) })} />
                    </div>
                  ))}
                  <Button type="link" icon={<PlusOutlined />} disabled={(draft.apps ?? []).length >= 8} style={{ paddingLeft: 0 }}
                    onClick={() => update(asset, { apps: [...(draft.apps ?? []), { alias: '', directory: '', includeJava: true, includeGo: false }] })}>添加应用目录</Button>
                </div>
              </Space>
            </Panel>
          );
        })}

        {problems.length > 0 && <Alert type="warning" showIcon message="下面的问题会让 Worker 拒绝加载这份配置" description={<ul style={{ margin: 0, paddingLeft: 18 }}>{problems.map(item => <li key={item}>{item}</li>)}</ul>} />}

        {drafts.length > 0 && <Panel title="ssh-config.json 预览"><pre aria-label="配置预览" style={box}>{text}</pre></Panel>}

        {drafts.length > 0 && <Panel title="在 Worker 上完成">
          <ol style={{ margin: 0, paddingLeft: 18, lineHeight: 1.9 }}>
            <li>把 ssh-config.json 放到 Worker 的私有目录（如 <Mono>runtime/ssh/</Mono>），私钥放在其中的相对路径并限制为仅本人可读。</li>
            <li>取得主机公钥后，<b>经运维通过可信渠道核对指纹</b>，再写入 <Mono>{knownHostsFile || 'known_hosts'}</Mono>：
              <pre style={{ ...box, marginTop: 6 }}>{keyscanCommands(drafts)}</pre></li>
            <li>在目标主机上为只读账号放入对应公钥；账号需能读取 <Mono>/etc/os-release</Mono> 和软件包数据库，主机需有 Python 3。</li>
            <li>用 <Mono>sec-worker --ssh-config runtime/ssh/ssh-config.json</Mono> 重启 Worker。</li>
            <li>创建自动综合扫描时把 SSH 端口包含在扫描范围内，结果会出现在任务详情的“检测覆盖”和本页的“最近扫描”。</li>
          </ol>
          <Paragraph style={{ ...muted, margin: '8px 0 0' }}>Worker 固定校验主机指纹并禁用密码登录；不会自动使用 sudo，也不会安装任何程序。</Paragraph>
        </Panel>}
      </Space>
    </Modal>
  );
};
