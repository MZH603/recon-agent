import {TuiMainScreen, Input, truncateToWidth} from '@earendil-works/pi-tui';

const fields=['api_base','model','api_key','target'];
const labels=['API 根地址','模型','API Key（仅本次进程）','目标（例如 example.com）'];
const limits={api_base:2048,model:256,api_key:4096,target:2048};
const errors={
 form:'配置格式无效，请重新填写。',
 api_base:'请输入 HTTP/HTTPS API 根地址；禁止凭据、查询、片段或 chat/completions 路径。',
 model:'请输入有效的单行模型名（最多 256 字符）。',
 api_key:'请输入本次使用的有效单行 API Key（最多 4096 字符）。',
 target:'请输入有效且允许的域名/IP/URL/CIDR；自有内网实验目标需 --lab。',
 authorized:'请明确确认已获本次目标的合法授权。',
};

class SecretInput extends Input {
 render(width){
  // The Pi renderer only ever sees a separate masked component. Raw input stays
  // in this setup child, never in Editor, history, Markdown or terminal frames.
  const masked=new Input({prompt:this.prompt,placeholder:this.placeholder});
  masked.setValue('*'.repeat(this.value.length));masked.cursor=this.cursor;masked.focused=this.focused;
  return masked.render(width);
 }
 dispose(){
  this.setValue('');this.cursor=0;this.pasteBuffer='';this.isInPaste=false;
  this.undoStack.clear();this.killRing.ring.length=0;this.lastAction=null;
  this.onSubmit=this.onEscape=undefined;
 }
}

export function createSetupView(terminal,send,onExit=()=>{}){
 const tui=new TuiMainScreen(terminal);
 const view={focus:0,authorized:false,busy:false,exitCode:0,inputs:{},errors:[],closed:false};
 fields.forEach(field=>view.inputs[field]=field==='api_key'?new SecretInput({prompt:'  '}):new Input({prompt:'  '}));
 function clear(){view.inputs.api_key?.dispose();view.inputs.api_key=null;}
 function move(step){view.focus=(view.focus+step+6)%6;}
 function quit(code){
  if(view.closed)return;
  view.exitCode=code;view.closed=true;clear();send({type:code===130?'cancel':'quit'});
  tui.requestRender();
 }
 const form={focused:false,invalidate(){},
  render(width){
   const lines=['启动配置 · L0 等待任务','API Key 仅本次进程使用；每次重新确认授权。'];
   fields.forEach((field,index)=>{
    const input=view.inputs[field];
    lines.push((view.focus===index?'› ':'  ')+labels[index]);
    if(input){input.focused=view.focus===index;lines.push(...input.render(Math.max(1,width)));}
    else lines.push('  已清空');
   });
   lines.push((view.focus===4?'› ':'  ')+(view.authorized?'[x]':'[ ]')+' 已获本次目标合法授权');
   lines.push((view.focus===5?'› ':'  ')+(view.busy?'提交中…':'[进入会话]'));
   lines.push(...view.errors,'Tab / Shift+Tab 切换 · Enter 下一项/确认 · Esc 退出');
   return lines.map(line=>truncateToWidth(line,Math.max(1,width),''));
  },
  handleInput(data){
   if(view.closed)return;
   if(data==='\x03'){quit(130);return;}
   if(data==='\x1b'){quit(0);return;}
   if(view.busy)return;
   const input=view.inputs[fields[view.focus]];
   if(input?.isInPaste){input.handleInput(data);input.pasteBuffer=input.pasteBuffer.slice(0,limits[fields[view.focus]]+6);}
   else if(data==='\t')move(1);
   else if(data==='\x1b[Z')move(-1);
   else if(data==='\r'||data==='\n'){
    if(view.focus<4)move(1);
    else if(view.focus===4)view.authorized=!view.authorized;
    else {
     view.busy=true;view.errors=[];
     send({type:'configure',...Object.fromEntries(fields.map(field=>[field,view.inputs[field].getValue()])),authorized:view.authorized});
    }
   }else if(view.focus===4&&data===' ')view.authorized=!view.authorized;
   else if(input)input.handleInput(data);
   if(input&&input.getValue().length>limits[fields[view.focus]])input.setValue(input.getValue().slice(0,limits[fields[view.focus]]));
   tui.requestRender();
  }
 };
 tui.addChild(form);tui.setFocus(form);
 view.form=form;
 view.handle=event=>{
  if(view.closed&&event.type!=='shutdown')return;
  if(event.type==='defaults'){
   for(const field of ['api_base','model','target'])if(typeof event[field]==='string')view.inputs[field].setValue(event[field]);
   view.inputs.api_key.placeholder=event.key_available?'已有 Key 可用；留空沿用':'请输入 API Key';
  }else if(event.type==='errors'){
   view.busy=false;
   // Only trusted fixed labels render. Never echo backend/user text as errors.
   view.errors=Object.keys(event.errors??{}).filter(key=>Object.hasOwn(errors,key)).map(key=>errors[key]);
  }else if(event.type==='accepted'||event.type==='shutdown'){
   view.exitCode=event.code??0;view.closed=true;clear();onExit(view.exitCode);
  }
  tui.requestRender();
 };
 view.start=()=>tui.start();
 view.stop=()=>{view.closed=true;clear();tui.stop();};
 return view;
}
