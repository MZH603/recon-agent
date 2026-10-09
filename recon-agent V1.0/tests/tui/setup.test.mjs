import test from 'node:test';
import assert from 'node:assert/strict';
import {visibleWidth} from './helpers.mjs';

import * as module from '../../cli/tui/setup.mjs';
const terminal={columns:40,rows:24,write(){},start(){},stop(){},hideCursor(){},showCursor(){}};

test('actual Pi input: Tab, ShiftTab, paste, delete, masking and narrow widths',()=>{
 const view=module.createSetupView(terminal,()=>{});
 view.handle({type:'defaults',api_base:'https://api.test/v1',model:'model',target:'',key_available:true});
 assert.equal(view.authorized,false);
 view.form.handleInput('\t');view.form.handleInput('\t');
 assert.equal(view.focus,2);
 view.form.handleInput('\x1b[200~dummy-secret-9384\x1b[201~');
 const secret=view.inputs.api_key;
 assert.equal(secret.getValue(),'dummy-secret-9384');
 view.form.handleInput('\x7f');
 assert.equal(secret.getValue(),'dummy-secret-938');
 for(const width of [1,5,16,40]){
  const lines=view.form.render(width);
  assert.ok(lines.every(line=>visibleWidth(line)<=width));
  assert.ok(!lines.join('').includes('dummy-secret'));
 }
 view.form.handleInput('\x1b[Z');assert.equal(view.focus,1);
 view.form.handleInput('\t');view.form.handleInput('\t');
 view.form.handleInput('\x1b[200~例子.example.org\x1b[201~');
 assert.equal(view.inputs.target.getValue(),'例子.example.org');
 view.form.handleInput('\r');assert.equal(view.focus,4);
 view.form.handleInput(' ');assert.equal(view.authorized,true);
});

test('one request in flight, fixed errors, corrected retry and discard sensitive components',()=>{
 const sent=[];let finished=0;
 const view=module.createSetupView(terminal,value=>sent.push(value),()=>finished++);
 view.handle({type:'defaults',api_base:'https://api.test/v1',model:'model',target:'example.org',key_available:false});
 for(let i=0;i<2;i++)view.form.handleInput('\t');
 view.form.handleInput('dummy-secret-9384');
 const secret=view.inputs.api_key;
 // Populate the real Input undo/kill ring/paste buffers before acceptance.
 view.form.handleInput('\x17');view.form.handleInput('corrected-key');
 for(let i=0;i<3;i++)view.form.handleInput('\t');
 view.form.handleInput('\r');view.form.handleInput('\r');
 assert.equal(sent.length,1);assert.equal(sent[0].authorized,false);
 view.handle({type:'errors',errors:{authorized:'dummy-secret-9384'}});
 assert.ok(!view.form.render(80).join('').includes('dummy-secret-9384'));
 view.form.handleInput('\x1b[Z');view.form.handleInput(' ');view.form.handleInput('\t');view.form.handleInput('\r');
 assert.equal(sent.length,2);assert.equal(sent[1].authorized,true);
 view.handle({type:'accepted'});
 assert.equal(finished,1);assert.equal(view.inputs.api_key,null);
 assert.equal(secret.getValue(),'');assert.equal(secret.pasteBuffer,'');
 assert.equal(secret.undoStack.pop(),undefined);assert.equal(secret.killRing.peek(),undefined);
 assert.ok(!JSON.stringify(view).includes('corrected-key'));
});

test('escape and CtrlC clear unfinished secret paste and exit safely',()=>{
 for(const [key,code,kind] of [['\x1b',0,'quit'],['\x03',130,'cancel']]){
  const sent=[];const view=module.createSetupView(terminal,value=>sent.push(value));
  view.form.handleInput('\t');view.form.handleInput('\t');
  const secret=view.inputs.api_key;view.form.handleInput('\x1b[200~unfinished-secret');
  view.form.handleInput(key);
  assert.deepEqual(sent,[{type:kind}]);assert.equal(view.exitCode,code);
  assert.equal(secret.pasteBuffer,'');assert.equal(view.inputs.api_key,null);
 }
});

for(const [field,focus,value] of [
  ['api_base',0,'https://api.test/'+'x'.repeat(301)],
  ['api_key',2,'key-'+ 'x'.repeat(2996)],
]){
 for(const [label,navigation] of [['Tab','\t'],['ShiftTab','\x1b[Z'],['Enter','\r']]){
  test(`${label} preserves the long ${field} value when leaving its field`,()=>{
   const view=module.createSetupView(terminal,()=>{});
   for(let i=0;i<focus;i++)view.form.handleInput('\t');
   // Exercise real paste/edit handling before leaving the field, rather than
   // setting an overlong component value that bypasses the field's edit limit.
   view.form.handleInput('\x1b[200~'+value+'\x1b[201~');
   assert.equal(view.inputs[field].getValue(),value);
   view.form.handleInput(navigation);
   assert.equal(view.inputs[field].getValue(),value,`${field} changed on ${JSON.stringify(navigation)}`);
   if(field==='api_key')assert.ok(!view.form.render(80).join('').includes(value));
   view.stop();
  });
 }
}

const toolRows=[
 {id:'custom:status',name:'status',kind:'http',enabled:false,min_level:1,status:'configured-http'},
 {id:'mcp:browser',name:'browser',kind:'mcp:stdio',enabled:false,min_level:2,status:'missing-script'},
];
const toolPath='C:\\tools\\tool-integrations.example.yaml';
function optionalView(rows=toolRows){
 const sent=[];
 const view=module.createSetupView(terminal,value=>sent.push(value));
 view.handle({type:'defaults',api_base:'https://api.test/v1',model:'model',target:'example.org',
  key_available:true,tools_config:toolPath,tools:rows});
 return {view,sent};
}
function focus(view,index){
 for(let count=0;view.focus!==index&&count<110;count++)view.form.handleInput('\t');
 assert.equal(view.focus,index,'keyboard focus must reach optional control');
}
function expand(view){focus(view,6);view.form.handleInput('\r');}
function submit(view){focus(view,5);view.form.handleInput('\r');}
function replacePath(view,path){
 focus(view,7);view.form.handleInput('\x01');view.form.handleInput('\x0b');
 view.form.handleInput('\x1b[200~'+path+'\x1b[201~');
}

test('optional tools start collapsed and direct entry keeps the legacy configure payload',()=>{
 const {view,sent}=optionalView();
 assert.ok(view.form.render(160).some(line=>line.includes('工具配置（可选）')));
 assert.ok(!view.form.render(160).some(line=>line.includes(toolPath)));
 submit(view);
 assert.deepEqual(sent,[{type:'configure',api_base:'https://api.test/v1',model:'model',api_key:'',
  target:'example.org',authorized:false}]);
});

test('expand alone keeps configured enabled tools and still skips optional overrides',()=>{
 const {view,sent}=optionalView([{...toolRows[0],enabled:true}]);
 expand(view);
 assert.ok(view.form.render(160).some(line=>line.includes('[x] status')));
 submit(view);
 assert.ok(!Object.hasOwn(sent[0],'selected_tools'));
 assert.ok(!Object.hasOwn(sent[0],'tools_config'));
});

test('keyboard loads a profile without a key and applies selected tools',()=>{
 const {view,sent}=optionalView();
 focus(view,2);view.form.handleInput('dummy-preview-secret');
 expand(view);replacePath(view,'C:\\profiles\\local.yaml');view.form.handleInput('\r');
 assert.deepEqual(sent,[{type:'inspect_tools',tools_config:'C:\\profiles\\local.yaml'}]);
 view.handle({type:'tool_options',tools_config:'C:\\profiles\\local.yaml',tools:toolRows});
 focus(view,10);view.form.handleInput(' ');
 focus(view,11);view.form.handleInput('\r');
 submit(view);
 assert.equal(sent.length,2);
 assert.equal(sent[1].tools_config,'C:\\profiles\\local.yaml');
 assert.deepEqual(sent[1].selected_tools,['custom:status','mcp:browser']);
 assert.equal(sent[1].api_key,'dummy-preview-secret');
});

test('explicitly unchecking all existing tools submits an empty selection',()=>{
 const {view,sent}=optionalView([{...toolRows[0],enabled:true}]);
 expand(view);focus(view,10);view.form.handleInput(' ');submit(view);
 assert.deepEqual(sent[0].selected_tools,[]);
 assert.equal(sent[0].tools_config,toolPath);
});

test('loading disabled examples without choosing a tool still allows direct entry',()=>{
 const {view,sent}=optionalView();
 expand(view);focus(view,8);view.form.handleInput('\r');
 view.handle({type:'tool_options',tools_config:toolPath,tools:toolRows});
 submit(view);
 assert.equal(sent[1].type,'configure');
 assert.ok(!Object.hasOwn(sent[1],'selected_tools'));
});

test('fixed preview errors recover through clear and skip without successful loading',()=>{
 const {view,sent}=optionalView();
 expand(view);replacePath(view,'missing.yaml');view.form.handleInput('\r');
 view.handle({type:'errors',errors:{tools_config:'dummy-error-secret'}});
 const text=view.form.render(200).join('\n');
 assert.ok(text.includes('工具配置'));assert.ok(!text.includes('dummy-error-secret'));
 submit(view);assert.equal(sent.length,1);
 focus(view,9);view.form.handleInput('\r');submit(view);
 assert.equal(sent.length,2);assert.equal(sent[1].type,'configure');
 assert.ok(!Object.hasOwn(sent[1],'tools_config'));
});

test('a bad profile can be edited and loaded again before selecting',()=>{
 const {view,sent}=optionalView();
 expand(view);replacePath(view,'missing.yaml');view.form.handleInput('\r');
 view.handle({type:'errors',errors:{tools_config:'no'}});
 replacePath(view,'good.yaml');focus(view,8);view.form.handleInput('\r');
 view.handle({type:'tool_options',tools_config:'good.yaml',tools:toolRows});
 focus(view,10);view.form.handleInput('\r');submit(view);
 assert.deepEqual(sent.map(value=>value.type),['inspect_tools','inspect_tools','configure']);
 assert.deepEqual(sent[2].selected_tools,['custom:status']);
});

test('an edited but unloaded path cannot submit a stale selection',()=>{
 const {view,sent}=optionalView();
 expand(view);focus(view,10);view.form.handleInput(' ');
 replacePath(view,'different.yaml');submit(view);
 assert.equal(sent.length,0);
 assert.ok(view.form.render(160).some(line=>line.includes('加载')&&line.includes('工具配置')));
 focus(view,9);view.form.handleInput('\r');submit(view);
 assert.ok(!Object.hasOwn(sent[0],'selected_tools'));
});

test('folding discards optional selection and dynamic controls wrap with ShiftTab',()=>{
 const {view,sent}=optionalView();
 expand(view);focus(view,10);view.form.handleInput(' ');
 focus(view,11);view.form.handleInput('\t');assert.equal(view.focus,0);
 view.form.handleInput('\x1b[Z');assert.equal(view.focus,11);
 focus(view,6);view.form.handleInput('\r');
 view.form.handleInput('\t');assert.equal(view.focus,0);
 view.form.handleInput('\x1b[Z');assert.equal(view.focus,6);
 submit(view);assert.ok(!Object.hasOwn(sent[0],'selected_tools'));
});

test('optional rendering shows fixed readiness and levels, masks keys and bounds path edits',()=>{
 const {view,sent}=optionalView(toolRows.map(row=>({...row,description:'dummy-metadata-secret',
  command:['dummy-command-secret'],env:{TOKEN:'dummy-env-secret'}})));
 focus(view,2);view.form.handleInput('dummy-render-secret');expand(view);
 const full=view.form.render(200).join('\n');
 assert.ok(full.includes('L1')&&full.includes('L2')&&full.includes('缺少脚本'));
 assert.ok(full.includes('浏览器')&&full.includes('YAML'));
 for(const width of [1,5,16,40,200]){
  const lines=view.form.render(width);
  assert.ok(lines.every(line=>visibleWidth(line)<=width));
  assert.ok(!lines.join('').includes('dummy-'));
 }
 replacePath(view,'x'.repeat(3000));
 assert.equal(view.inputs.tools_config.getValue().length,2048);
 view.form.handleInput('\r');
 assert.equal(sent[0].tools_config.length,2048);
 assert.deepEqual(Object.keys(sent[0]),['type','tools_config']);
});

test('clear during preview ignores late results and permits direct entry',()=>{
 const {view,sent}=optionalView();
 expand(view);focus(view,8);view.form.handleInput('\r');
 view.form.handleInput('\r');assert.equal(sent.length,1);
 focus(view,9);view.form.handleInput('\r');
 view.handle({type:'tool_options',tools_config:toolPath,tools:[{...toolRows[0],enabled:true}]});
 submit(view);assert.equal(sent.length,2);
 assert.ok(!Object.hasOwn(sent[1],'tools_config'));
});

test('large tool lists keep the focused control visible on the terminal viewport',()=>{
 const {view}=optionalView(Array.from({length:101},(_,index)=>({...toolRows[0],
  id:`custom:tool${index}`,name:`tool${index}`})));
 expand(view);focus(view,10);
 assert.equal(view.tools.length,100);
 let lines=view.form.render(120);
 assert.ok(lines.length<=terminal.rows);
 assert.ok(lines.slice(-terminal.rows).some(line=>line.includes('› [ ] tool0')));
 focus(view,109);
 assert.ok(view.form.render(120).slice(-terminal.rows).some(line=>line.includes('› [ ] tool99')));
 focus(view,5);
 assert.ok(view.form.render(120).slice(-terminal.rows).some(line=>line.includes('› [进入会话]')));
});

test('unknown readiness and kind values cannot resolve inherited object properties',()=>{
 const {view}=optionalView([{...toolRows[0],kind:'constructor',status:'toString'}]);
 expand(view);
 const text=view.form.render(200).join('\n');
 assert.ok(text.includes('扩展工具')&&text.includes('就绪状态未知'));
 assert.ok(!text.includes('[native code]'));
});

test('escape during preview clears secrets and ignores late backend responses',()=>{
 const {view,sent}=optionalView();
 focus(view,2);view.form.handleInput('dummy-pending-secret');
 const secret=view.inputs.api_key;
 expand(view);focus(view,8);view.form.handleInput('\r');view.form.handleInput('\x1b');
 view.handle({type:'tool_options',tools_config:toolPath,tools:toolRows});
 assert.deepEqual(sent.map(command=>command.type),['inspect_tools','quit']);
 assert.equal(secret.getValue(),'');assert.equal(view.inputs.api_key,null);
 assert.equal(view.closed,true);
 assert.ok(!JSON.stringify(view).includes('dummy-pending-secret'));
});
