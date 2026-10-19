#!/usr/bin/env python3
"""Exercise local ordinary functions against disposable SQLite/rules. No target is contacted."""
import datetime as dt
import hashlib
import http.cookiejar
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'Local-Only-Test-Password-2026'  # Disposable test fixture, never a real account.

class API:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(self, method, path, body=None, expect=200, data=None, content_type=None):
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        if content_type:
            headers['Content-Type'] = content_type
        request = urllib.request.Request(self.base+path, data=data, method=method, headers=headers)
        try:
            response = self.opener.open(request, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read()
        if response.code != expect:
            raise AssertionError(f'{method} {path}: {response.code} != {expect}; {raw[:400]!r}')
        return json.loads(raw) if raw and raw[:1] in (b'{', b'[') else raw
    def login(self, name):
        return self.call('POST', '/api/v1/auth/login', {'username': name, 'password': PASSWORD})

def until(check, timeout=20):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        result=check()
        if result:
            return result
        time.sleep(.15)
    raise AssertionError('Timed out waiting for local state')

def archive(version, corrupt=False):
    files={'nuclei/templates/local.yaml':b'id: local-metadata-fixture\n', 'trivy/db/metadata.json':b'{"localTest":true}\n'}
    manifest={'version':version,'engines':['nuclei','trivy'],'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    if corrupt:
        manifest['files']['nuclei/templates/local.yaml']='0'*64
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest.json',json.dumps(manifest))
        for name,data in files.items():
            z.writestr(name,data)
    return out.getvalue()

def main():
    supplied=os.environ.get('SCANNER_QA_DIR')
    directory=Path(supplied) if supplied else Path(tempfile.mkdtemp(prefix='scanner-platform-local-'))
    directory.mkdir(parents=True,exist_ok=True)
    db=directory/'platform.db'
    if db.exists():
        raise SystemExit('Use a NEW QA directory; refusing to modify an existing database.')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    processes={};logs=[]
    def start(name):
        log=open(directory/(name+'.log'),'ab');logs.append(log)
        args=[str(ROOT/'dist'/('sec-'+name))]
        if name=='server':
            args+=['--listen',f'127.0.0.1:{port}','--db',str(db),'--ui-dir',str(ROOT/'web/dist'),'--seed-demo']
        else:
            args+=['--server',base]
            if name=='updater':args+=['--rules-dir',str(directory/'rules')]
            if name=='worker':args+=['--rules-dir',str(directory/'rules'),'--runtime-dir',str(directory/'worker'),'--inputs-dir',str(directory/'inputs')]
        processes[name]=subprocess.Popen(args,cwd=ROOT,stdout=log,stderr=log)
    def ready():
        try:
            return API(base).call('GET','/readyz')
        except (OSError,AssertionError):
            return False
    checks=0
    def checkpoint(label):
        nonlocal checks
        checks+=1
        print('PASS '+label,flush=True)
    try:
        start('server');until(ready)
        start('worker');start('updater')
        api=API(base)
        assert b'<html' in api.call('GET','/').lower()
        assert api.call('GET','/api/v1/auth/setup')['required']
        api.call('GET','/api/v1/tasks',expect=401)
        api.call('POST','/api/v1/auth/setup',{'username':'localadmin','password':PASSWORD},expect=201)
        api.call('POST','/api/v1/auth/setup',{'username':'otheradmin','password':PASSWORD},expect=409)
        admin=api.login('localadmin')
        checkpoint('first-run setup, login, same-origin UI and authenticated task API')
        for name,role in [('localviewer','viewer'),('localops','ops_approver')]:
            api.call('POST','/api/v1/users',{'username':name,'password':PASSWORD,'role':role},expect=201)
        users=api.call('GET','/api/v1/users')['items']
        viewer_id=next(u['id'] for u in users if u['username']=='localviewer')
        viewer=API(base);viewer.login('localviewer')
        viewer.call('GET','/api/v1/users',expect=403)
        api.call('PATCH','/api/v1/users/'+viewer_id,{'role':'viewer','isActive':False})
        viewer.call('GET','/api/v1/auth/me',expect=401)
        api.call('PATCH','/api/v1/users/'+viewer_id,{'role':'viewer','isActive':True});viewer.login('localviewer')
        api.call('PATCH','/api/v1/users/'+admin['id'],{'role':'viewer','isActive':False},expect=403)
        checkpoint('user creation, role restrictions, disabling/re-enabling and last-admin protection')
        asset_body={'kind':'host','address':'192.0.2.20','businessGroup':'Local QA','owner':'Example owner','requestedPorts':[80,443],'skippedPorts':[443]}
        asset=api.call('POST','/api/v1/assets',asset_body,expect=201)
        api.call('POST','/api/v1/assets',asset_body,expect=409)
        api.call('POST','/api/v1/assets',{**asset_body,'address':'192.0.2.0/24'},expect=400)
        api.call('POST','/api/v1/assets',{**asset_body,'address':'example.com'},expect=400)
        api.call('POST','/api/v1/assets',{**asset_body,'address':'2001:db8::20','requestedPorts':[8443],'skippedPorts':[]},expect=201)
        api.call('POST','/api/v1/assets',{'kind':'image_repo','address':'registry.example.com/qa/image','businessGroup':'Local QA','owner':'Example owner','requestedPorts':[]},expect=201)
        updated=api.call('PATCH','/api/v1/assets/'+asset['id'],{'businessGroup':'Local QA edited','owner':'Example owner','requestedPorts':[80,443,8080],'skippedPorts':[443]})
        assert updated['skippedPorts']==[443]
        viewer.call('POST','/api/v1/assets',asset_body,expect=403)
        checkpoint('IPv4/IPv6/image registry, edits, duplicates, CIDR/domain rejection and skip ports')
        expiry=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=2)).isoformat()
        scope=api.call('POST','/api/v1/scopes',{'assetId':asset['id'],'timeWindows':[{'weekdays':[0,1,2,3,4,5,6],'start':'23:00','end':'05:00','timeZone':'Asia/Shanghai'}],'expiresAt':expiry},expect=201)
        decision={'decision':'APPROVE','approvalTicket':'LOCAL-EXAMPLE-001','note':'Local test fixture'}
        api.call('POST','/api/v1/scopes/'+scope['id']+'/review',decision,expect=403)
        ops=API(base);ops.login('localops')
        approved=ops.call('POST','/api/v1/scopes/'+scope['id']+'/review',decision)
        assert approved['isActive']
        ops.call('POST','/api/v1/scopes/'+scope['id']+'/review',decision,expect=409)
        ops.call('POST',f'/api/v1/port-requests/{asset["id"]}/80/review',{**decision,'kind':'WEB'})
        ops.call('POST',f'/api/v1/port-requests/{asset["id"]}/443/review',{**decision,'kind':'WEB'},expect=409)
        ops.call('POST',f'/api/v1/port-requests/{asset["id"]}/8080/review',{**decision,'decision':'REJECT'})
        checkpoint('scope/port approval, overnight window records, self-review denial and skip preservation')
        body={'synthetic':True,'targets':['192.0.2.20:80','192.0.2.20:443'],'timeWindows':[]}
        task=api.call('POST','/api/v1/tasks',body,expect=201)
        assert task['targetCount']==1 and task['skippedTargets']==['192.0.2.20:443']
        def task_state(task_id):
            return next((t for t in api.call('GET','/api/v1/tasks')['items'] if t['id']==task_id),None)
        until(lambda:task_state(task['id'])['status']=='COMPLETED')
        finding=next(f for f in api.call('GET','/api/v1/findings')['items'] if f['taskId']==task['id'])
        assert finding['synthetic'] and finding['target']=='192.0.2.20:80' and finding['businessGroup']=='Local QA edited'
        api.call('PATCH','/api/v1/findings/'+finding['id'],{'status':'IN_PROGRESS'})
        api.call('PATCH','/api/v1/findings/'+finding['id'],{'status':'FALSE_POSITIVE'})
        api.call('PATCH','/api/v1/findings/'+finding['id'],{'status':'FIXED'},expect=400)
        viewer.call('POST','/api/v1/tasks',body,expect=403)
        api.call('POST','/api/v1/tasks',{**body,'targets':['192.0.2.20:22']},expect=400)
        canceled=api.call('POST','/api/v1/tasks',body,expect=201)
        api.call('POST','/api/v1/tasks/'+canceled['id']+'/cancel')
        until(lambda:task_state(canceled['id'])['status']=='CANCELED')
        checkpoint('explicit-target dispatch, worker completion, stored finding, status changes and cancellation')
        due=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=3)).isoformat()
        schedule=api.call('POST','/api/v1/schedules',{**body,'name':'One local run','nextRun':due,'intervalMinutes':0},expect=201)
        def schedule_state():
            return next(s for s in api.call('GET','/api/v1/schedules')['items'] if s['id']==schedule['id'])
        until(lambda:schedule_state()['lastTaskId'])
        until(lambda:task_state(schedule_state()['lastTaskId'])['status']=='COMPLETED')
        assert not schedule_state()['enabled']
        api.call('PATCH','/api/v1/schedules/'+schedule['id'],{'enabled':True})
        api.call('PATCH','/api/v1/schedules/'+schedule['id'],{'enabled':False})
        tomorrow=(dt.datetime.now(dt.timezone.utc).weekday()+2)%7
        waiting=api.call('POST','/api/v1/tasks',{**body,'timeWindows':[{'weekdays':[tomorrow],'start':'00:00','end':'24:00','timeZone':'UTC'}]},expect=201)
        assert waiting['status']=='WAITING_WINDOW'
        checkpoint('automatic scheduled firing, one-shot state, schedule enable/disable and outside-window waiting')
        def import_zip(version,corrupt=False):
            boundary='scanner-local-boundary'
            data=(f'--{boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="rules.zip"\r\nContent-Type: application/zip\r\n\r\n'.encode()+archive(version,corrupt)+f'\r\n--{boundary}--\r\n'.encode())
            return api.call('POST','/api/v1/rules/import',expect=202,data=data,content_type='multipart/form-data; boundary='+boundary)
        def job_done(job):
            item=next(j for j in api.call('GET','/api/v1/rule-jobs')['items'] if j['id']==job['id'])
            return item if item['status'] in ('FAILED','COMPLETED') else None
        def expect_job(job,status='COMPLETED'):
            result=until(lambda:job_done(job))
            assert result['status']==status,result
        for version in ['20261016.01','20261016.02']:
            expect_job(import_zip(version))
            expect_job(api.call('POST',f'/api/v1/rules/{version}/activate',{'rollback':False},expect=202))
        expect_job(import_zip('20261016.03',True),'FAILED')
        assert (directory/'rules/CURRENT').read_text()=='20261016.02\n'
        expect_job(api.call('POST','/api/v1/rules/20261016.01/activate',{'rollback':False},expect=202),'FAILED')
        expect_job(api.call('POST','/api/v1/rules/20261016.01/activate',{'rollback':True},expect=202))
        assert (directory/'rules/CURRENT').read_text()=='20261016.01\n'
        catalog=api.call('GET','/api/v1/rules')['items']
        assert len(catalog)==2 and all(b['integrityVerified'] and not b['signatureVerified'] and not b['engineValidated'] for b in catalog)
        api.call('POST','/api/v1/rules/fetch',{'url':'http://rules.example.com/bundle.zip','expectedSha256':'0'*64},expect=400)
        viewer.call('POST','/api/v1/rules/20261016.01/activate',{'rollback':True},expect=403)
        checkpoint('offline ZIP import, Updater-only writes, activation, failed-hash rejection and explicit rollback')
        capabilities=api.call('GET','/api/v1/detection-capabilities')['items']
        assert next(c for c in capabilities if c['id']=='weak_credential')['status']=='disabled'
        policy=api.call('GET','/api/v1/scan-policy')
        policy['exclusions']=[{'start':81,'end':82}]
        api.call('PUT','/api/v1/scan-policy',policy)
        viewer.call('PUT','/api/v1/scan-policy',policy,expect=403)
        entry={'id':'EXAMPLE-LOCAL-001','title':'示例知识条目','component':'example-component',
               'description':'仅用于本地业务回归','impact':'示例影响','solution':'示例建议',
               'references':['https://example.org/advisory'],'source':'示例公开公告摘要','language':'zh-CN',
               'cvssScore':7.5,'affectedRanges':[{'introduced':'1.0','fixed':'2.0'}]}
        api.call('POST','/api/v1/knowledge',entry,expect=201)
        assert api.call('GET','/api/v1/knowledge')['total']==1
        api.call('PUT','/api/v1/knowledge/'+entry['id'],{**entry,'title':'已更新的示例条目'})
        api.call('DELETE','/api/v1/knowledge/'+entry['id'])
        assert api.call('GET','/api/v1/knowledge')['total']==0
        checkpoint('detection capability status, administrator scan policy and offline knowledge CRUD')
        report=api.call('POST','/api/v1/reports',{'format':'html','scope':{'taskId':task['id']}},expect=202)
        def report_ready(report_id):
            item=api.call('GET','/api/v1/reports/'+report_id)
            assert item['status']!='FAILED',item
            return item if item['status']=='READY' else None
        until(lambda:report_ready(report['id']))
        html=api.call('GET','/api/v1/reports/'+report['id']+'/download')
        assert report['snapshotId'].encode() in html and '本次未启用该检测项'.encode() in html
        for output_format in ['xlsx','docx']:
            other=api.call('POST','/api/v1/reports/'+report['id']+'/formats',{'format':output_format},expect=202)
            assert other['snapshotId']==report['snapshotId']
            until(lambda:report_ready(other['id']))
            data=api.call('GET','/api/v1/reports/'+other['id']+'/download')
            with zipfile.ZipFile(io.BytesIO(data)) as output:
                assert output.testzip() is None
                if output_format=='xlsx':assert len([name for name in output.namelist() if name.startswith('xl/worksheets/sheet') and name.endswith('.xml')])==8
        viewer.call('POST','/api/v1/reports',{'format':'html'},expect=403)
        checkpoint('background reports, authenticated downloads and same-snapshot HTML/Excel/Word exports')
        assert len(api.call('GET','/api/v1/nodes')['items'])==2
        processes['worker'].terminate();processes['worker'].wait(timeout=8)
        until(lambda:any(n['kind']=='worker' and n['status']=='OFFLINE' for n in api.call('GET','/api/v1/nodes')['items']),timeout=15)
        start('worker');until(lambda:any(n['kind']=='worker' and n['status']=='ONLINE' for n in api.call('GET','/api/v1/nodes')['items']))
        checkpoint('real local worker/updater heartbeat, offline detection and recovery')
        processes['server'].terminate();processes['server'].wait(timeout=8);start('server');until(ready)
        assert len(api.call('GET','/api/v1/assets')['items'])==3
        assert task_state(task['id'])['status']=='COMPLETED'
        assert len(api.call('GET','/api/v1/rules')['items'])==2
        assert api.call('GET','/api/v1/schedules')['total']==1
        assert api.call('GET','/api/v1/reports')['total']==3
        with sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True) as connection:
            assert connection.execute('SELECT count(*) FROM audit_logs').fetchone()[0]>=15
        api.call('POST','/api/v1/auth/logout');api.call('GET','/api/v1/auth/me',expect=401)
        checkpoint('restart persistence, retained session, catalog/schedule records, audit and logout')
        (directory/'result.json').write_text(json.dumps({'result':'PASS','scanning':False,'serverURL':base,'checks':checks},indent=2))
        print('ALL LOCAL CHECKS PASSED; evidence directory: '+str(directory),flush=True)
    finally:
        for process in processes.values():
            if process.poll() is None:process.terminate()
        for process in processes.values():
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for log in logs:log.close()

if __name__=='__main__':
    main()
