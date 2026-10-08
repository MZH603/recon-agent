import test from 'node:test';
import assert from 'node:assert/strict';
import {visibleWidth} from '@earendil-works/pi-tui';

const module = await import('./setup.mjs').catch(()=>({}));
const terminal={columns:40,rows:24,write(){},start(){},stop(){},hideCursor(){},showCursor(){}};

test('setup form module exists',()=>assert.equal(typeof module.createSetupView,'function'));

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
