import {TuiMainScreen, Input, truncateToWidth} from '@earendil-works/pi-tui';

const fields=['api_base','model','api_key','target'];
const labels=['API 根地址','模型','API Key（仅本次进程）','目标（例如 example.com）'];
const limits={api_base:2048,model:256,api_key:4096,target:2048,tools_config:2048};
const errors={
 form:'配置格式无效，请重新填写。',
 api_base:'请输入 HTTP/HTTPS API 根地址；禁止凭据、查询、片段或 chat/completions 路径。',
 model:'请输入有效的单行模型名（最多 256 字符）。',
 api_key:'请输入本次使用的有效单行 API Key（最多 4096 字符）。',
 target:'请输入有效且允许的域名/IP/URL/CIDR；自有内网实验目标需 --lab。',
 authorized:'请明确确认已获本次目标的合法授权。',
 tools_config:'工具配置无效或路径已修改；请重新加载，或清除并跳过。',
};
const readiness={
 'executable-found':'已找到可执行程序',
 'missing-executable':'缺少可执行程序',
 'missing-script':'缺少脚本',
 'template-executable':'需配置可执行程序路径',
 'requires-native-executable':'需配置原生可执行程序',
 'requires-bandit':'需安装 Bandit',
 'bandit-found':'已找到 Bandit',
 'configured-http':'HTTP 配置已就绪',
 'manual-hint':'手动执行提示',
 'requires-api-key':'需配置服务凭据环境变量',
};
const kinds={command:'命令',script:'脚本',shell:'手动命令',http:'HTTP','mcp:stdio':'MCP stdio','mcp:http':'MCP HTTP','extension:command':'受控 CLI','extension:search':'搜索情报','extension:proxy':'代理只读查询'};
function toolRows(rows){
 return (Array.isArray(rows)?rows:[]).slice(0,100)
  .filter(row=>row&&typeof row.id==='string'&&typeof row.name==='string')
  .map(row=>({id:row.id,name:row.name.replace(/[\x00-\x1f\x7f-\x9f]/g,'').slice(0,256),
   kind:Object.hasOwn(kinds,row.kind)?kinds[row.kind]:'扩展工具',enabled:row.enabled===true,
   min_level:Number.isInteger(row.min_level)&&row.min_level>=0&&row.min_level<=5?row.min_level:0,
   status:Object.hasOwn(readiness,row.status)?readiness[row.status]:'就绪状态未知'}));
}

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
 const view={focus:0,authorized:false,busy:false,exitCode:0,inputs:{},errors:[],closed:false,
  toolsExpanded:false,tools:[],selectedTools:new Set(),selectionChanged:false,profileChanged:false,
  loadedToolsConfig:'',toolsError:false,preview:null};
 let defaultTools={path:'',tools:[]};
 fields.forEach(field=>view.inputs[field]=field==='api_key'?new SecretInput({prompt:'  '}):new Input({prompt:'  '}));
 view.inputs.tools_config=new Input({prompt:'  ',placeholder:'留空使用原有工具配置'});
 function clear(){view.inputs.api_key?.dispose();view.inputs.api_key=null;}
 function move(step){
  const count=view.toolsExpanded?10+view.tools.length:7;
  view.focus=(view.focus+step+count)%count;
 }
 function resetTools(){
  if(view.preview)view.preview.discarded=true;
  view.inputs.tools_config.setValue(defaultTools.path);
  view.inputs.tools_config.cursor=defaultTools.path.length;
  view.tools=defaultTools.tools;
  view.selectedTools=new Set(view.tools.filter(row=>row.enabled).map(row=>row.id));
  view.loadedToolsConfig=defaultTools.path;
  view.selectionChanged=view.profileChanged=view.toolsError=false;
  view.errors=view.errors.filter(error=>error!==errors.tools_config);
  view.toolsExpanded=false;view.focus=6;
 }
 function previewTools(){
  if(view.preview)return;
  const path=view.inputs.tools_config.getValue();
  view.preview={path,discarded:false};view.profileChanged=true;view.toolsError=false;
  view.errors=view.errors.filter(error=>error!==errors.tools_config);
  // Metadata preview intentionally never includes credentials or auth fields.
  send({type:'inspect_tools',tools_config:path});
 }
 function submit(){
  if(view.preview&&!view.preview.discarded)return;
  if(view.toolsError||view.inputs.tools_config.getValue()!==view.loadedToolsConfig){
   view.errors=[...view.errors.filter(error=>error!==errors.tools_config),errors.tools_config];return;
  }
  const optional=view.selectionChanged||(view.profileChanged&&view.selectedTools.size>0)
   ?{tools_config:view.loadedToolsConfig,selected_tools:view.tools.filter(row=>view.selectedTools.has(row.id)).map(row=>row.id)}:{};
  view.busy=true;view.errors=[];
  send({type:'configure',...Object.fromEntries(fields.map(field=>[field,view.inputs[field].getValue()])),
   authorized:view.authorized,...optional});
 }
 function activate(){
  if(view.focus===4)view.authorized=!view.authorized;
  else if(view.focus===5)submit();
  else if(view.focus===6){if(view.toolsExpanded)resetTools();else view.toolsExpanded=true;}
  else if(view.focus===9)resetTools();
  else if(view.focus===7||view.focus===8)previewTools();
  else if(view.focus>=10&&!view.preview&&!view.toolsError&&view.inputs.tools_config.getValue()===view.loadedToolsConfig){
   const row=view.tools[view.focus-10];
   if(view.selectedTools.has(row.id))view.selectedTools.delete(row.id);else view.selectedTools.add(row.id);
   view.selectionChanged=true;
  }
 }
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
   lines.push(...view.errors);
   lines.push((view.focus===6?'› ':'  ')+(view.toolsExpanded?'[-]':'[+]')+' 工具配置（可选）');
   if(view.toolsExpanded){
    lines.push('  内置工具始终可用；不选择可直接进入。');
    lines.push('  选择仅本次进程生效；收起或清除会丢弃修改。');
    lines.push('  浏览器依赖需安装，脚本路径请在本机 YAML 中配置。');
    lines.push((view.focus===7?'› ':'  ')+'工具 YAML 路径（留空使用原有配置）');
    view.inputs.tools_config.focused=view.focus===7;
    lines.push(...view.inputs.tools_config.render(Math.max(1,width)));
    lines.push((view.focus===8?'› ':'  ')+(view.preview&&!view.preview.discarded?'预览加载中…':'[加载工具列表]'));
    lines.push((view.focus===9?'› ':'  ')+'[清除并跳过工具配置]');
    view.tools.forEach((row,index)=>{
     lines.push((view.focus===10+index?'› ':'  ')+(view.selectedTools.has(row.id)?'[x] ':'[ ] ')+row.name+
      ` · ${row.kind} · L${row.min_level} · ${row.status}`);
    });
    if(!view.tools.length)lines.push('  当前没有扩展工具；可直接进入。');
    if(view.inputs.tools_config.getValue()!==view.loadedToolsConfig)lines.push('  工具配置路径已修改，请加载后再选择或清除并跳过。');
   }
   lines.push('Tab / Shift+Tab 切换 · Enter 下一项/确认 · Esc 退出');
   // Pi's main screen displays the bottom terminal-height rows. Keep a focused
   // window so long tool lists cannot scroll the current control out of view.
   const height=Math.max(1,terminal.rows??24);
   const focused=Math.max(0,lines.findIndex(line=>line.startsWith('› ')))+(view.focus<4||view.focus===7?1:0);
   const start=Math.max(0,Math.min(focused-Math.floor(height/2),lines.length-height));
   return lines.slice(start,start+height).map(line=>truncateToWidth(line,Math.max(1,width),''));
  },
  handleInput(data){
   if(view.closed)return;
   if(data==='\x03'){quit(130);return;}
   if(data==='\x1b'){quit(0);return;}
   if(view.busy)return;
   const field=view.focus===7?'tools_config':fields[view.focus],input=view.inputs[field],limit=limits[field];
   const previous=input?.getValue();
   if(input?.isInPaste){input.handleInput(data);input.pasteBuffer=input.pasteBuffer.slice(0,limit+6);}
   else if(data==='\t')move(1);
   else if(data==='\x1b[Z')move(-1);
   else if(data==='\r'||data==='\n'){
    if(view.focus<4)move(1);
    else activate();
   }else if((view.focus===4||view.focus===6||view.focus>=10)&&data===' ')activate();
   else if(input&&!(field==='tools_config'&&view.preview))input.handleInput(data);
   if(input&&input.getValue().length>limit)input.setValue(input.getValue().slice(0,limit));
   if(field==='tools_config'&&input.getValue()!==previous)view.profileChanged=true;
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
   defaultTools={path:typeof event.tools_config==='string'?event.tools_config.slice(0,2048):'',tools:toolRows(event.tools)};
   const focus=view.focus;resetTools();view.focus=focus;
  }else if(event.type==='tool_options'){
   const preview=view.preview;view.preview=null;
   if(preview&&!preview.discarded){
    view.tools=toolRows(event.tools);view.selectedTools=new Set(view.tools.filter(row=>row.enabled).map(row=>row.id));
    view.loadedToolsConfig=preview.path;view.selectionChanged=false;view.toolsError=false;
    view.focus=Math.min(view.focus,9+view.tools.length);
   }
  }else if(event.type==='errors'){
   const preview=view.preview;view.preview=null;
   if(!preview?.discarded){
    view.busy=false;
    view.toolsError=Object.hasOwn(event.errors??{},'tools_config');
    // Only trusted fixed labels render. Never echo backend/user text as errors.
    view.errors=Object.keys(event.errors??{}).filter(key=>Object.hasOwn(errors,key)).map(key=>errors[key]);
   }
  }else if(event.type==='accepted'||event.type==='shutdown'){
   view.exitCode=event.code??0;view.closed=true;clear();onExit(view.exitCode);
  }
  tui.requestRender();
 };
 view.start=()=>tui.start();
 view.stop=()=>{view.closed=true;clear();tui.stop();};
 return view;
}
