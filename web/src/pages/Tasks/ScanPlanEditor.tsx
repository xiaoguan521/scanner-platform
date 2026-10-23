import React, { useEffect, useState } from 'react';
import { Form, Input, message, Modal, Select, Space } from 'antd';
import { errorMessage } from '../../api/client';
import { createScanPlan, updateScanPlan } from '../../api/runtime';
import { presetLabels } from './policy';
import type { CustomRule, ScanPlan, ScanPlanInput } from '../../types';

type PlanEditorValues=ScanPlanInput;
/** A preset is always copied; a custom plan can be edited in place or copied. */
export interface PlanEditorTarget { plan: ScanPlan; copy: boolean }

export const ScanPlanEditor:React.FC<{target:PlanEditorTarget|null;customRules:CustomRule[];onSaved:(plan:ScanPlan,replaced:boolean)=>void;onClose:()=>void}>=({target,customRules,onSaved,onClose})=>{
  const [form]=Form.useForm<PlanEditorValues>();
  const [busy,setBusy]=useState(false);
  const editingPlan=target&&!target.copy?target.plan:null;
  useEffect(()=>{
    if(!target){form.resetFields();return;}
    const {plan,copy}=target;
    form.setFieldsValue({title:copy?`${plan.title}（自定义）`:plan.title,summary:plan.summary,detail:plan.detail,defaults:{...plan.defaults,customRuleIds:[...(plan.defaults.customRuleIds??[])]},sourceId:plan.kind==='PRESET'?plan.id:plan.sourceId});
  },[target,form]);
  const save=async(values:PlanEditorValues)=>{
    setBusy(true);
    try{
      const saved=editingPlan?await updateScanPlan(editingPlan.id,values):await createScanPlan(values);
      onSaved(saved,Boolean(editingPlan));onClose();message.success(editingPlan?'自定义扫描方案已更新':'自定义扫描方案已保存');
    }catch(cause){message.error(errorMessage(cause,'保存扫描方案失败'));}finally{setBusy(false);}
  };
  return <>
  <Modal title={editingPlan?'编辑自定义扫描方案':'复制为自定义扫描方案'} open={Boolean(target)} width={680} onCancel={()=>{if(!busy)onClose();}} onOk={()=>form.submit()} okText="保存方案" cancelText="取消" confirmLoading={busy} destroyOnClose maskClosable={!busy}>
    <Form<PlanEditorValues> form={form} layout="vertical" onFinish={save} initialValues={{defaults:{portPreset:'common',intensity:'gentle',portRanges:'',portExclusions:'',customRuleIds:[]}}}>
      <Form.Item name="sourceId" hidden><Input /></Form.Item>
      <Form.Item name="title" label="方案名称" rules={[{required:true,message:'请输入方案名称'},{max:80,message:'方案名称不能超过 80 个字符'}]}><Input maxLength={80}/></Form.Item>
      <Form.Item name="summary" label="一句话说明" rules={[{required:true,message:'请输入一句话说明'},{max:200,message:'说明不能超过 200 个字符'}]}><Input maxLength={200}/></Form.Item>
      <Form.Item name="detail" label="检测范围与影响" rules={[{required:true,message:'请说明检测范围和影响'},{max:600,message:'说明不能超过 600 个字符'}]}><Input.TextArea rows={3} maxLength={600}/></Form.Item>
      <Space wrap style={{display:'flex'}} align="start">
        <Form.Item name={['defaults','portPreset']} label="探测范围" rules={[{required:true}]} style={{minWidth:260}}><Select options={Object.entries(presetLabels).map(([value,label])=>({value,label}))}/></Form.Item>
        <Form.Item name={['defaults','intensity']} label="扫描强度" rules={[{required:true}]} style={{minWidth:220}}><Select options={[{value:'gentle',label:'温和'},{value:'standard',label:'标准'},{value:'aggressive',label:'积极'}]}/></Form.Item>
      </Space>
      <Form.Item noStyle shouldUpdate={(previous,current)=>previous.defaults?.portPreset!==current.defaults?.portPreset}>{({getFieldValue})=>{
        const preset=getFieldValue(['defaults','portPreset']);
        return ['custom','common-and-custom'].includes(preset)?<Form.Item name={['defaults','portRanges']} label="自定义 TCP 端口范围" rules={[{required:true,message:'自定义范围方案必须填写端口范围'}]} extra="英文逗号分隔，例如 22, 8080-8090。平台保存和创建任务时都会再次校验。"><Input placeholder="例如 22,18080"/></Form.Item>:null;
      }}</Form.Item>
      <Form.Item name={['defaults','portExclusions']} label="默认排除端口或范围" extra="可留空；系统、资产和任务排除仍会在创建任务时合并。"><Input placeholder="例如 443,8000-8010"/></Form.Item>
      <Form.Item name={['defaults','customRuleIds']} label="默认自定义规则" extra="只保存已启用规则的选择；规则状态和权限仍由平台在创建任务时复核。"><Select mode="multiple" allowClear showSearch optionFilterProp="label" options={customRules.filter(rule=>rule.enabled).map(rule=>({value:rule.id,label:`${rule.name} · ${rule.severity}`}))} maxTagCount="responsive" placeholder="留空表示全部启用规则"/></Form.Item>
    </Form>
  </Modal>
  </>;
};
