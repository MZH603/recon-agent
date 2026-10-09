import test from 'node:test';
import assert from 'node:assert/strict';
import { createView } from '../../cli/tui/view.mjs';
import { visibleWidth } from './helpers.mjs';
import { taskPanel } from '../../cli/tui/layout.mjs';

test('context is independent from cumulative tokens and legacy token caps',()=>{
 const panel=taskPanel({used_tokens:900000,max_tokens:10000,session_used_tokens:1500000,
  context_tokens:20000,context_capacity:100000,context_trigger_tokens:70000,context_estimated:true,
  used_cost:1.8,max_cost:2,usage_estimated_calls:3,cost_unknown_calls:2});
 assert.match(panel,/上下文/);assert.match(panel,/20,000 \/ 100,000.*20%/);
 assert.match(panel,/压缩触发.*70,000/);
 assert.doesNotMatch(panel,/累计消耗|估算用量|费用未知|费用预算|\$|1,500,000|9000%|接近上限|等待预算|tokens.*10,000/);
});

test('live context events refresh compression immediately without clearing active state',()=>{
 const view=createView(new FakeTerminal(),()=>{});
 try {
  view.handle({type:'state',task_id:'task',status:'running',busy:true,plan:'保留计划',context_capacity:100000,
   pending:{kind:'authorization',interrupt_id:'auth',question:'确认授权'}});
  const count=view.transcript.children.length,loader=view.loader;
  view.handle({type:'context',context_tokens:45000,context_capacity:100000,context_trigger_tokens:70000,
   context_before_tokens:78000,context_saved_tokens:33000,context_compactions:2,context_compressed:true,context_estimated:true});
  assert.equal(view.currentState.context_tokens,45000);assert.equal(view.currentState.plan,'保留计划');
  assert.equal(view.currentState.pending.interrupt_id,'auth');assert.equal(view.transcript.children.length,count);
  assert.equal(view.loader,loader);assert.ok(view.busy);assert.match(view.loader.message,/压缩/);
  assert.match(view.layout.sidebar.text,/78,000.*45,000/);assert.match(view.layout.sidebar.text,/节省.*33,000/);
  assert.match(view.layout.sidebar.text,/压缩.*2.*次/);
  view.handle({type:'context',context_tokens:47000,context_before_tokens:47000,
   context_saved_tokens:0,context_compressed:false});
  assert.match(view.layout.sidebar.text,/47,000 \/ 100,000/);
  assert.match(view.layout.sidebar.text,/上次压缩 78,000 → 45,000/,'ordinary estimates retain the last actual compression');
  view.handle({type:'state',status:'paused',busy:false,pending:{kind:'context_limit',question:'缩短必需内容'}});
  assert.equal(view.busy,false);assert.match(view.layout.sidebar.text,/上下文超限/);
  view.handle({type:'context',context_tokens:100001,context_limited:true});
  assert.equal(view.busy,false,'late context update cannot restart a paused task');
 } finally {view.stop();}
});

test('context with no measurement is unknown rather than zero',()=>{
 assert.match(taskPanel({}),/上下文[\s\S]*未知/);
 assert.doesNotMatch(taskPanel({}),/0 \/ 100,000/);
});

class FakeTerminal {
  columns=45; rows=16; frames=[];
  start(onInput,onResize){this.onInput=onInput;this.onResize=onResize;}
  stop(){this.stopped=true;}
  write(text){this.frames.push(text);}
  hideCursor(){} showCursor(){} clearLine(){} moveBy(){} clearFromCursor(){}
}
test('L2 retry redisplays identical authorization prompts but status does not duplicate them',()=>{
 const sent=[],view=createView(new FakeTerminal(),command=>sent.push(command));
 const prompt={type:'state',status:'paused',level:1,pending:{kind:'authorization',interrupt_id:'first',question:'请输入 CONFIRM 2 继续'}};
 const denied={type:'state',status:'paused',level:1,pending:{kind:'authorization_denied',interrupt_id:'denied',question:'An exact L2 confirmation was declined.',options:['Continue','Stop']}};
 try {
  view.handle(prompt);view.editor.onSubmit('y');view.handle(denied);
  view.editor.onSubmit('continue');
  const count=view.transcript.children.length;
  view.handle({...prompt,pending:{...prompt.pending,interrupt_id:'retry'}});
  assert.equal(view.transcript.children.length,count+1,'retry must display the confirmation again');
  assert.equal(view.busy,false);
  const shown=view.transcript.children.length;
  view.handle({...prompt,pending:{...prompt.pending,interrupt_id:'retry'}});
  assert.equal(view.transcript.children.length,shown,'status refresh is the same pending prompt');
  view.editor.onSubmit('Continue');
  const next=view.transcript.children.length;
  view.handle({...denied,pending:{...denied.pending,interrupt_id:'denied-again'}});
  assert.equal(view.transcript.children.length,next+1,'a new denial must remain visible');
  assert.deepEqual(sent.map(item=>item.text),['y','continue','Continue']);
 } finally {view.stop();}
});
test('actual Editor submits multiline input, keeps history and shows immediate loader',()=>{
 const terminal=new FakeTerminal(), sent=[];
 const view=createView(terminal, command=>sent.push(command));
 view.start();
 view.editor.setText('中文\n第二行'); view.editor.onSubmit(view.editor.getText());
 assert.deepEqual(sent,[{type:'input',text:'中文\n第二行'}]);
 assert.ok(view.busy); assert.ok(view.loader);
 view.editor.setText('重复'); view.editor.onSubmit('重复'); assert.equal(sent.length,1);
 view.handle({type:'state',status:'paused',level:0,pending:{kind:'question',question:'下一步？'}});
 assert.equal(view.busy,false);
 view.handle({type:'preview',id:'1',text:'# 中文长回答\n'+ '中文很长 '.repeat(200)});
 view.handle({type:'preview',id:'1',text:'# 中文长回答\n'+ '中文很长 '.repeat(400)});
 const lines=view.transcript.render(45);
 assert.ok(lines.length>20); assert.ok(lines.every(line=>visibleWidth(line)<=45));
 const count=view.transcript.children.length;
 view.handle({type:'state',status:'finished',level:0,answer:'# 中文长回答\n'+ '中文很长 '.repeat(400)});
 assert.equal(view.transcript.children.length,count);
 view.stop(); assert.ok(terminal.stopped);
});
test('Ctrl+C cancels and exits with 130',()=>{
 const sent=[], view=createView(new FakeTerminal(), command=>sent.push(command));
 view.handleInput('\x03');
 assert.deepEqual(sent,[{type:'cancel',exit:true}]); assert.equal(view.exitCode,130);
 view.stop();
});
test('status while running retains loading and full long segmented Markdown',()=>{
 const sent=[],view=createView(new FakeTerminal(),command=>sent.push(command));
 view.editor.onSubmit('task');
 view.handle({type:'state',status:'running',busy:true,level:0});
 assert.ok(view.busy);assert.ok(view.loader);
 view.editor.onSubmit('duplicate');assert.equal(sent.length,1);
 const answer='中文段落 '.repeat(6000)+'尾标记';
 for(let offset=0;offset<answer.length;offset+=6000)view.handle({type:'preview',id:'long',offset,text:answer.slice(offset,offset+6000)});
 assert.ok(view.transcript.render(45).join('\n').includes('尾标记'));
 view.stop();
});
test('restored state and status display a saved plan',()=>{
 const view=createView(new FakeTerminal(),()=>{});
 view.handle({type:'state',status:'idle',level:0,plan:'先查询 DNS，再总结来源。'});
 assert.ok(view.transcript.render(45).join('\n').includes('计划: 先查询 DNS，再总结来源。'));
 view.stop();
});
test('actual Editor Enter preserves a rejected busy draft and still accepts status',()=>{
 const sent=[],view=createView(new FakeTerminal(),command=>sent.push(command));
 try {
  view.editor.setText('first task');view.editor.handleInput('\r');
  const draft='第二条任务\n保留多行草稿';
  view.editor.setText(draft);view.editor.handleInput('\r');
  assert.equal(sent.length,1);assert.equal(view.editor.getText(),draft);
  view.editor.setText('status');view.editor.handleInput('\r');
  assert.deepEqual(sent[1],{type:'input',text:'status'});assert.equal(view.editor.getText(),'');
 } finally {view.stop();}
});

test('responsive task panel renders Chinese and real artifact paths within terminal columns',()=>{
 const terminal=new FakeTerminal(),view=createView(terminal,()=>{},()=>{},{theme:'light',color:false});
 try {
  view.handle({type:'state',task_id:'task-中文',status:'paused',level:1,context_capacity:100000,context_tokens:20000,context_trigger_tokens:70000,used_tokens:1200,
   session_used_tokens:4500,max_cost:2,used_cost:0.4,session_used_cost:1.2,
   plan:'查询来源并整理证据。',pending:{kind:'budget',question:'提高预算？'},
   results:[{name:'webfetch',status:'success',summary:'获取证据',evidence:['https://example.test/来源'],
    artifacts:[{id:'a1',path:'D:/真实位置/证据.json',purpose:'原始响应'}]}]});
  assert.ok(view.layout,'view exposes the actual responsive component');
  view.start();
  for(const width of [32,45,80,120]) {
   terminal.columns=width;
   view.editor.onSubmit('/sidebar');
   const lines=view.layout.render(width);
   assert.ok(lines.every(line=>visibleWidth(line)<=width),`overflow at ${width} columns`);
   assert.ok(lines.join('\n').includes('上下文'));
   const pages=[...lines];
   for(let page=0;page<8;page++){
    view.handleInput('\x1b[6~');pages.push(...view.layout.render(width));
   }
   assert.ok(pages.join('\n').includes('计划'));
   assert.ok(!pages.join('\n').includes('会话累计消耗'));
   const scrolled=view.layout.render(width);
   assert.ok(scrolled.every(line=>visibleWidth(line)<=width));
   assert.ok(scrolled.join('\n').includes('证据.json'),'PgDn reveals the actual artifact location');
   assert.ok(!lines.join('').includes('\x1b['),'NO_COLOR theme has no styling');
   view.tui.renderNow();
   assert.ok(view.tui.captureRenderState().previousLines.every(line=>visibleWidth(line)<=width),'actual FakeTerminal frame stays within width');
   view.editor.onSubmit('/sidebar');
  }
  assert.ok(terminal.frames.length);
  view.handle({type:'state',task_id:'task-中文',status:'completed',busy:false});
  assert.equal(view.currentState.pending,null,'terminal state clears an omitted pending prompt');
  assert.match(view.layout.sidebar.text,/已完成/);
 } finally {view.stop();}
});

test('/new is forwarded while busy and new task resets preview deduplication',()=>{
 const sent=[],view=createView(new FakeTerminal(),command=>sent.push(command));
 try {
  view.handle({type:'state',task_id:'old',status:'running',busy:true});
  view.handle({type:'preview',id:'p',offset:0,text:'旧任务回复'});
  view.editor.onSubmit('/new');assert.deepEqual(sent,[{type:'input',text:'/new'}]);
  view.handle({type:'state',task_id:'new',status:'idle',busy:false});
  assert.ok(!view.transcript.render(45).join('\n').includes('旧任务回复'));
  view.handle({type:'preview',id:'p',offset:0,text:'新任务回复  \n'});
  const count=view.transcript.children.length;
  view.handle({type:'state',task_id:'new',status:'finished',answer:'新任务回复'});
  assert.equal(view.transcript.children.length,count);
 } finally {view.stop();}
});

test('waiting tools remain running and timeout and late results have distinct summaries',()=>{
 const sent=[],view=createView(new FakeTerminal(),command=>sent.push(command));
 try {
  view.handle({type:'tool',phase:'tool_wait',execution_id:'e1',name:'webfetch',elapsed_seconds:17,timeout_seconds:30,status:'running'});
  assert.ok(view.busy);assert.match(view.loader.message,/17.*30/);
  view.editor.onSubmit('/details');assert.equal(sent.length,0);
  view.handle({type:'tool',phase:'tool_end',execution_id:'e1',name:'webfetch',success:false,
   result:{status:'timeout',summary:'等待超时',outcome_unknown:true,error:'迟到仍可能有副作用'}});
  const text=view.transcript.render(80).join('\n');assert.match(text,/超时/);assert.match(text,/副作用未知/);
  view.handle({type:'tool',phase:'tool_late',execution_id:'e1',result:{name:'webfetch',success:true}});
  assert.match(view.transcript.render(80).join('\n'),/webfetch.*迟到.*诊断/);
 } finally {view.stop();}
});
