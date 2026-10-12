// Real frontend entrypoints with a local bridge fixture; no internal module imports.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {stripVTControlCharacters} from 'node:util';
import {setTimeout as delay} from 'node:timers/promises';

for (const [entry, event, marker] of [
  ['app.mjs', {type: 'note', text: 'session-smoke-ready'}, 'session-smoke-ready'],
  ['setup-app.mjs', {type: 'defaults', target: 'setup-smoke.invalid',
    api_base: 'http://127.0.0.1:1/v1', model: 'fixture', key_available: false}, 'setup-smoke.invalid'],
]) {
  test(`${entry} starts, authenticates, renders and exits`, {timeout: 20000}, async t => {
    const server = net.createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    let socket;
    let hello;
    let stdout = '';
    let stderr = '';
    let shutdown = false;
    const token = 'local-smoke-token';
    const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP']);
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toUpperCase())));
    Object.assign(env, {RECON_TUI_PORT: String(server.address().port), RECON_TUI_TOKEN: token, TERM: 'xterm-256color'});
    server.on('connection', client => {
      socket = client;
      let pending = '';
      client.on('error', () => {});
      client.on('data', bytes => {
        pending += bytes.toString('utf8');
        const index = pending.indexOf('\n');
        if (index < 0 || hello) return;
        hello = JSON.parse(pending.slice(0, index));
        client.write(JSON.stringify(event) + '\n');
      });
    });
    const child = spawn(process.execPath, [fileURLToPath(new URL(`../../cli/tui/${entry}`, import.meta.url))],
      {env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
    t.after(() => {
      if (!shutdown) t.diagnostic(`hello=${JSON.stringify(hello)} stdout=${JSON.stringify(stdout)} stderr=${stderr}`);
      child.stdin.destroy();
      if (child.exitCode === null) child.kill();
      socket?.destroy();
      server.close();
    });
    child.stdout.on('data', bytes => {
      stdout += bytes.toString('utf8');
      if (!shutdown && stripVTControlCharacters(stdout).includes(marker)) {
        shutdown = true;
        socket.write(JSON.stringify({type: 'shutdown', code: 0}) + '\n');
      }
    });
    child.stderr.on('data', bytes => {stderr += bytes.toString('utf8');});
    const code = await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => reject(new Error(
        `Frontend did not render/exit. hello=${JSON.stringify(hello)} stdout=${stdout} stderr=${stderr}`)), 15000);
      t.after(() => clearTimeout(deadline));
      child.once('error', reject);
      child.once('close', resolve);
    });
    assert.equal(code, 0, stdout + stderr);
    assert.deepEqual(hello, {type: 'hello', token});
    assert.ok(shutdown && stripVTControlCharacters(stdout).includes(marker), stdout + stderr);
  });
}

// Interact with the shipped app and its public bridge, never frontend internals.
async function sessionFixture(t, extraEnv={}) {
  const server=net.createServer();
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const allowed=new Set(['PATH','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','TEMP','TMP']);
  const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>allowed.has(key.toUpperCase())));
  Object.assign(env,{RECON_TUI_PORT:String(server.address().port),RECON_TUI_TOKEN:'interaction-token',
    TERM:'xterm-256color',COLORTERM:'truecolor',COLUMNS:'120',RECON_TUI_THEME:'dark'},extraEnv);
  let socket,stdout='',stderr='';const commands=[];
  server.on('connection',client=>{
    socket=client;let pending='';client.on('error',()=>{});
    client.on('data',bytes=>{
      pending+=bytes.toString('utf8');
      while(pending.includes('\n')) {
        const index=pending.indexOf('\n'),frame=JSON.parse(pending.slice(0,index));pending=pending.slice(index+1);
        if(frame.type==='hello')client.write(JSON.stringify({type:'note',text:'interaction-ready'})+'\n');
        else commands.push(frame);
      }
    });
  });
  const child=spawn(process.execPath,[fileURLToPath(new URL('../../cli/tui/app.mjs',import.meta.url))],
    {env,stdio:['pipe','pipe','pipe'],windowsHide:true});
  child.stdout.on('data',bytes=>{stdout+=bytes.toString('utf8');});
  child.stderr.on('data',bytes=>{stderr+=bytes.toString('utf8');});
  const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});
  t.after(()=>{child.stdin.destroy();if(child.exitCode===null)child.kill();socket?.destroy();server.close();});
  async function waitFor(predicate,label) {
    const deadline=Date.now()+6000;
    while(!predicate()) {
      assert.equal(child.exitCode,null,`Frontend exited: ${stdout}\n${stderr}`);
      assert.ok(Date.now()<deadline,`Timed out waiting for ${label}: ${stripVTControlCharacters(stdout)}\n${stderr}`);
      await delay(20);
    }
  }
  const fixture={commands,read:()=>stripVTControlCharacters(stdout),raw:()=>stdout,
    input:text=>child.stdin.write(text),emit:event=>socket.write(JSON.stringify(event)+'\n'),waitFor,
    async finish(){socket.write(JSON.stringify({type:'shutdown',code:0})+'\n');assert.equal(await closed,0,stderr);}};
  await waitFor(()=>fixture.read().includes('interaction-ready'),'initial render');
  return fixture;
}

test('conversation layout discovers slash commands and routes controls without model input',{timeout:20000},async t=>{
  const app=await sessionFixture(t);
  assert.doesNotMatch(app.read(),/F2|F3|任务栏|PgUp\/PgDn/);
  app.emit({type:'state',task_id:'task-one',status:'idle',model:'fixture-model',context_tokens:1200,
    context_capacity:10000,used_cost:0.012,max_cost:2,cost_unknown_calls:0,plan:'检查目标',results:[]});
  await app.waitFor(()=>app.read().includes('fixture-model'),'model status');
  assert.match(app.read(),/12%|1,200|1200/);
  app.emit({type:'activity',text:'切换备用模型',model:'fixture-fallback-model'});
  await app.waitFor(()=>app.read().includes('fixture-fallback-model'),'live fallback model metadata');
  const beforeReset=app.raw().length;
  app.emit({type:'activity',text:'等待模型',model:'fixture-primary-model'});
  await app.waitFor(()=>app.raw().slice(beforeReset).includes('fixture-primary-model'),'next call resets model metadata');
  app.emit({type:'state',task_id:'task-one',status:'idle',model:'fixture-model'});
  app.input('/');
  await app.waitFor(()=>app.read().includes('/status')&&app.read().includes('/help'),'slash menu');
  app.input('\x1b');await delay(50);app.input('\x15/sta');
  await delay(120);app.input('\t\r');
  await app.waitFor(()=>app.commands.some(command=>command.type==='status'),'completed status command');
  app.emit({type:'state',task_id:'task-one',status:'idle',model:'fixture-model',plan:'unsolicited-plan',
    results:[{artifacts:[{path:'stale-unsolicited-path'}]}]});
  await app.waitFor(()=>app.read().includes('unsolicited-plan'),'unsolicited state');
  assert.doesNotMatch(app.read(),/stale-unsolicited-path/);
  app.emit({type:'state',status_requested:true,task_id:'task-one',status:'idle',model:'fixture-model',plan:'状态计划',
    results:[{name:'fixture-tool',status:'success',summary:'状态结果',artifacts:[{id:'a1',path:'reports/fixture.json',purpose:'证据报告'}]}]});
  await app.waitFor(()=>app.read().includes('reports/fixture.json'),'on-demand status details');
  const count=app.commands.length;
  app.input('\x15/doesnotexist\r');
  await app.waitFor(()=>/未知命令|未找到命令|不支持的命令/.test(app.read()),'unknown command rejection');
  await delay(100);assert.equal(app.commands.length,count);
  app.input('\x15/help');await delay(100);app.input('\x1b');await delay(30);app.input('\r');
  await app.waitFor(()=>app.read().includes('/budget cost'),'local help');
  assert.equal(app.commands.length,count);
  for(const text of ['/budget tokens 1','/budget cost 0x10','/budget cost NaN','/budget cost -1','/stop extra']) {
    app.input('\x15'+text+'\r');await delay(100);
    assert.equal(app.commands.length,count,text+' must not reach Python or model');
  }
  app.input('\x15/budget');await delay(100);app.input('\t');
  await app.waitFor(()=>app.read().includes('/budget cost '),'budget completion and parameter hint');
  app.input('1\r');
  await app.waitFor(()=>app.commands.some(command=>command.type==='input'&&command.text==='/budget cost 1'),'valid budget input frame');
  for(const name of ['report','stop','abort','quit']) {
    app.input('\x15/'+name);await delay(100);app.input('\x1b');await delay(80);app.input('\r');
    await app.waitFor(()=>app.commands.some(command=>command.type===name),'canonical '+name+' control frame');
  }
  app.input('\x15/new');await delay(100);app.input('\x1b');await delay(80);app.input('\r');
  await app.waitFor(()=>app.commands.some(command=>command.type==='input'&&command.text==='/new'),'new input frame');
  await app.finish();
});

test('tools appear at start, preserve updates and bound summaries until details requested',{timeout:20000},async t=>{
  const app=await sessionFixture(t);
  app.emit({type:'tool',phase:'tool_start',execution_id:'tool-one',name:'fixture_lookup',arguments:{target:'example.invalid'}});
  await app.waitFor(()=>app.read().includes('fixture_lookup'),'tool start in transcript');
  assert.match(app.read(),/example\.invalid/);
  app.emit({type:'tool',phase:'tool_wait',execution_id:'tool-one',name:'fixture_lookup',elapsed_seconds:2,timeout_seconds:20});
  await app.waitFor(()=>app.read().includes('2s'),'progress update');
  const afterWait=app.raw().length;
  app.input('/details');await delay(100);app.input('\x1b');await delay(80);app.input('\r');
  await app.waitFor(()=>app.raw().slice(afterWait).includes('example.invalid'),'arguments survive wait updates in details');
  app.emit({type:'tool',phase:'tool_end',execution_id:'tool-one',name:'fixture_lookup',success:true,elapsed:3,
    result:{status:'success',summary:'summary-first\nsummary-second\nsummary-third\nsummary-hidden-fourth',data:{detail:'detail-only-marker'}}});
  await app.waitFor(()=>app.read().includes('summary-first'),'completion summary');
  assert.match(app.read(),/fixture_lookup · 完成/);
  assert.match(app.raw(),/\x1b\[38;2;147;159;162m/,'tool content uses gray');
  assert.doesNotMatch(app.read(),/summary-hidden-fourth|detail-only-marker/);
  app.emit({type:'state',task_id:'task-one',status:'idle'});
  app.input('/details');await delay(100);app.input('\x1b');await delay(30);app.input('\r');
  await app.waitFor(()=>app.read().includes('detail-only-marker'),'explicit tool details');
  assert.match(app.read(),/桥接传输已限长/);
  assert.equal(app.commands.length,0);
  app.emit({type:'tool',phase:'tool_late',execution_id:'tool-one',name:'fixture_lookup',result:{status:'late',summary:'late-result'}});
  await app.waitFor(()=>app.read().includes('迟到结果'),'late-result diagnostic');
  app.emit({type:'tool',phase:'tool_end',execution_id:'failed-tool',name:'failed_fixture',success:false,elapsed:1,
    result:{status:'failure',summary:'generic failure summary',error:'specific-failure-reason'}});
  await app.waitFor(()=>app.read().includes('specific-failure-reason'),'failure reason with a summary');
  app.emit({type:'tool',phase:'tool_end',execution_id:'timeout-tool',name:'timeout_fixture',success:false,
    result:{status:'timeout',error:'deadline-exceeded',outcome_unknown:true}});
  await app.waitFor(()=>app.read().includes('超时')&&app.read().includes('副作用未知'),'timeout and unknown outcome');
  app.emit({type:'tool',phase:'tool_cancelled',execution_id:'cancelled-tool',name:'cancelled_fixture',elapsed:4});
  await app.waitFor(()=>app.read().includes('执行是否停止未确认'),'cancellation diagnostic');
  app.emit({type:'tool',phase:'tool_end',execution_id:'partial-tool',name:'partial_fixture',success:false,
    result:{status:'partial',summary:'partial-evidence-saved'}});
  await app.waitFor(()=>app.read().includes('部分完成')&&app.read().includes('partial-evidence-saved'),'partial completion');
  await app.finish();
});

test('narrow NO_COLOR view keeps status and preserves a busy draft',{timeout:20000},async t=>{
  const app=await sessionFixture(t,{NO_COLOR:'1',COLUMNS:'42'});
  app.emit({type:'state',task_id:'busy-task',status:'running',busy:true,model:'very-long-fixture-model-name',
    context_tokens:500,context_capacity:1000});
  await app.waitFor(()=>app.read().includes('50%'),'narrow context status');
  app.input('keep-this-draft\r');
  await app.waitFor(()=>app.read().includes('keep-this-draft'),'busy draft');
  await delay(100);assert.equal(app.commands.length,0);
  assert.doesNotMatch(app.raw(),/\x1b\[[0-9;:]*m/);
  app.emit({type:'state',task_id:'busy-task',status:'idle',busy:false});await delay(80);
  app.input('\r');
  await app.waitFor(()=>app.commands.some(command=>command.type==='input'&&command.text==='keep-this-draft'),'retained draft submission');
  app.emit({type:'tool',phase:'tool_end',execution_id:'wrapped-tool',name:'wrapped_fixture',success:true,
    result:{status:'success',summary:'wrapped-visible '.repeat(16)+'wrapped-hidden-marker'}});
  await app.waitFor(()=>app.read().includes('摘要已截断'),'summary bounded after wrapping at narrow width');
  assert.doesNotMatch(app.read(),/wrapped-hidden-marker/);
  app.input('/details');await delay(100);app.input('\x1b');await delay(80);app.input('\r');
  await app.waitFor(()=>app.read().includes('wrapped-hidden-marker'),'wrapped summary details');
  await app.finish();
});

test('explicit and automatic themes recolor existing conversation text',{timeout:20000},async t=>{
  const light=await sessionFixture(t,{RECON_TUI_THEME:'light'});
  light.emit({type:'tool',phase:'tool_start',execution_id:'light-tool',name:'light_fixture'});
  await light.waitFor(()=>light.read().includes('light_fixture'),'light tool');
  assert.match(light.raw(),/\x1b\[38;2;89;102;106m/,'readable gray for light terminals');
  await light.finish();
  const auto=await sessionFixture(t,{RECON_TUI_THEME:'auto'});
  auto.emit({type:'tool',phase:'tool_start',execution_id:'auto-tool',name:'auto_fixture'});
  auto.emit({type:'preview',id:'theme-preview',text:'# Existing heading',offset:0});
  await auto.waitFor(()=>auto.read().includes('Existing heading'),'existing themed Markdown');
  const before=auto.raw().length;
  auto.input('\x1b[?997;2n');
  await auto.waitFor(()=>auto.raw().slice(before).includes('89;102;106'),'auto light color notification');
  assert.match(auto.raw().slice(before),/auto_fixture/,'existing tool content is repainted');
  assert.match(auto.raw().slice(before),/\x1b\[38;2;0;108;120m/,'existing title and Markdown use light accent');
  await auto.finish();
});

test('input footer places model on the left and token compression hints on the right',{timeout:20000},async t=>{
  const app=await sessionFixture(t,{NO_COLOR:'1'});
  app.emit({type:'state',task_id:'footer-task',status:'idle',model:'footer-fixture-model',
    context_tokens:1200,context_capacity:10000,context_trigger_tokens:7000,context_compactions:0});
  await app.waitFor(()=>app.read().includes('footer-fixture-model'),'model footer');
  const footer=app.read().split(/[\r\n]+/).find(line=>line.includes('footer-fixture-model')&&line.includes('1,200'));
  assert.ok(footer,'model and occupied context tokens share the footer');
  assert.match(footer,/footer-fixture-model\s{2,}.*1,200.*10,000.*70%.*压缩/);
  const border=app.read().lastIndexOf('─'.repeat(20));
  assert.ok(app.read().lastIndexOf(footer)>border,'metadata is below the input border');
  const before=app.raw().length;
  app.emit({type:'context',context_tokens:3000,context_capacity:10000,context_trigger_tokens:7000,
    context_compactions:1,context_compressed:true,context_saved_tokens:5000,context_before_tokens:8000});
  await app.waitFor(()=>/3,000.*已压缩.*1/.test(stripVTControlCharacters(app.raw().slice(before))),'live compression footer');
  await app.finish();
  const narrow=await sessionFixture(t,{NO_COLOR:'1',COLUMNS:'42'});
  narrow.emit({type:'state',task_id:'narrow-footer',status:'idle',model:'model-with-a-long-name',
    context_tokens:500,context_capacity:1000,context_trigger_tokens:700,context_compactions:0});
  await narrow.waitFor(()=>/500.*50%.*70%.*压缩/.test(narrow.read()),'compact footer retains token and compression hint');
  const line=narrow.read().split(/[\r\n]+/).find(line=>/500.*50%.*70%.*压缩/.test(line));
  assert.match(line,/model.*\s{2,}.*500/,'narrow footer keeps a visible model name');
  await narrow.finish();
});
