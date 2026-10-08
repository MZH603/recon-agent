import test from 'node:test';
import assert from 'node:assert/strict';
import { createView } from './view.mjs';
import { visibleWidth } from '@earendil-works/pi-tui';

class FakeTerminal {
  columns=45; rows=16; frames=[];
  start(onInput,onResize){this.onInput=onInput;this.onResize=onResize;}
  stop(){this.stopped=true;}
  write(text){this.frames.push(text);}
  hideCursor(){} showCursor(){} clearLine(){} moveBy(){} clearFromCursor(){}
}
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
