import React, {useState} from 'react';
import { DataTable } from '../../components/DataState';
import {Alert, Button, Checkbox, message, Modal, Space, Typography} from 'antd';
import {apiClient,errorMessage} from '../../api/client';
import {assertImportFile,canConfirmImport} from './import';
import { formatTime } from '../../utils/time';
import type {AssetImportPreview,AssetImportRow} from './import';

export const AssetImport:React.FC<{disabled:boolean;onImported:()=>Promise<void>}>=({disabled,onImported})=>{
  const [open,setOpen]=useState(false);
  const [preview,setPreview]=useState<AssetImportPreview|null>(null);
  const [accepted,setAccepted]=useState(false);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const upload=async(file:File)=>{
    setPreview(null);setAccepted(false);setError('');setBusy(true);
    try {assertImportFile(file);setPreview(await apiClient.previewAssetImport(file));}
    catch(cause){setError(errorMessage(cause,'预览失败'));}
    finally{setBusy(false);}
  };
  const confirm=async()=>{
    if(!canConfirmImport(preview,accepted,busy))return;
    setBusy(true);setError('');
    try {
      const result=await apiClient.confirmAssetImport(preview!.previewId!);
      // Clear the consumed token before refreshing, so a refresh error cannot re-submit it.
      setPreview(null);setAccepted(false);
      message.success(`已导入 ${result.imported} 条资产`);
      await onImported();setOpen(false);
    }catch(cause){setPreview(null);setAccepted(false);setError(errorMessage(cause,'确认失败，请重新预览'));}
    finally{setBusy(false);}
  };
  return <>
    <Button disabled={disabled} onClick={()=>{setOpen(true);setPreview(null);setAccepted(false);setError('');}}>CSV 导入</Button>
    <Modal title="预览并确认资产导入" open={open} width={1000} closable={!busy} maskClosable={!busy} keyboard={!busy} onCancel={()=>{if(!busy)setOpen(false);}} footer={<Space>
      <Button disabled={busy} onClick={()=>setOpen(false)}>取消</Button>
      <Button type="primary" loading={busy} disabled={!canConfirmImport(preview,accepted,busy)} onClick={()=>void confirm()}>确认导入 {preview?.valid??0} 条资产</Button>
    </Space>}>
      <Space direction="vertical" style={{width:'100%'}} size="middle">
        <Alert type="info" showIcon message="UTF-8 CSV，最多 1 MiB / 1000 行" description="按模板填写 kind,address,businessGroup,owner,name；name 列可省略。host 仅支持数字 IP。预览不会登记资产或测试连接，存在错误时请修改文件后重新上传。确认会整批新增台账，不添加端口或扫描授权。"/>
        <Space><Button href="/api/v1/assets/import/template" download>下载 CSV 模板</Button><input type="file" accept=".csv,text/csv" disabled={busy} aria-label="选择资产 CSV 文件" onChange={e=>{const file=e.target.files?.[0];e.target.value='';if(file)void upload(file);}}/></Space>
        {error&&<Alert type="error" showIcon message={error}/>}
        {preview&&<>
          <Typography.Text>共 {preview.total} 行，可导入 {preview.valid} 行，错误 {preview.invalid} 行。{preview.expiresAt?`预览有效至 ${formatTime(preview.expiresAt)}，新预览会替换旧预览。`:''}</Typography.Text>
          <DataTable<AssetImportRow> size="small" rowKey="row" dataSource={preview.rows} pagination={{pageSize:10}} scroll={{x:850}} columns={[
            {title:'行',dataIndex:'row',width:55},{title:'类型',dataIndex:'kind',width:100},{title:'地址',dataIndex:'address',ellipsis:true},{title:'业务组',dataIndex:'businessGroup',ellipsis:true},{title:'负责人',dataIndex:'owner',ellipsis:true},{title:'名称',dataIndex:'name',ellipsis:true},{title:'校验结果',dataIndex:'reason',render:(reason:string)=>reason||'可导入'},
          ]}/>
          <Checkbox checked={accepted} disabled={preview.invalid>0||busy} onChange={e=>setAccepted(e.target.checked)}>我已核对以上资产，确认整批导入台账</Checkbox>
        </>}
      </Space>
    </Modal>
  </>;
};
