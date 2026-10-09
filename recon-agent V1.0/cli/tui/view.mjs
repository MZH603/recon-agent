import {TuiMainScreen,Container,Text,Markdown,Editor,Loader,matchesKey,Key,styleText,parseColor} from '@earendil-works/pi-tui';
import {TaskLayout,statusLabel,taskPanel} from './layout.mjs';

const plain=text=>text;
const markdownKeys=['heading','link','linkUrl','code','codeBlock','codeBlockBorder','quote','quoteBorder','hr','listBullet','bold','italic','strikethrough','underline'];
const normalized=text=>String(text??'').trimEnd();
const seconds=value=>Number(value??0).toFixed(1).replace(/\.0$/,'');

export function createView(terminal,send,onExit=()=>{},options={}) {
 const tui=new TuiMainScreen(terminal);
 const transcript=new Container(),bottom=new Container(),state=new Text('',1,0),sidebar=new Text('',1,0);
 const requestedTheme=options.theme??process.env.RECON_TUI_THEME??process.env.RECON_THEME;
 const automaticTheme=!['light','dark'].includes(requestedTheme);
 let scheme=automaticTheme?(process.env.COLORFGBG?.split(';').at(-1)==='15'?'light':'dark'):requestedTheme;
 const color=options.color??!(process.env.NO_COLOR!==undefined||process.env.TERM==='dumb');
 const paint=(text,attrs={})=>color?styleText(text,{bold:attrs.bold,
  fg:attrs.accent?parseColor(scheme==='light'?'#006c78':'#81c7cf'):attrs.muted?parseColor(scheme==='light'?'#59666a':'#939fa2'):undefined}):text;
 const accent=text=>paint(text,{accent:true}),muted=text=>paint(text,{muted:true});
 const theme=Object.fromEntries(markdownKeys.map(key=>[key,plain]));
 Object.assign(theme,{heading:text=>paint(text,{bold:true,accent:true}),bold:text=>paint(text,{bold:true}),code:accent});
 const editorTheme={borderColor:accent,selectList:{selectedPrefix:accent,selectedText:accent,description:muted,scrollInfo:muted,noMatch:muted}};
 const editor=new Editor(tui,editorTheme,{paddingX:1});
 const previews=new Map(),shown=new Set(),tools=new Map();
 let pendingShown=null;
 const view={tui,transcript,editor,busy:false,loader:null,exitCode:0,details:false,currentState:{status:'idle'}};
 const clean=color?plain:text=>text.replace(/\x1b\[[0-9;:]*m/g,'');
 const layout=new TaskLayout(terminal,transcript,bottom,sidebar,paint,clean);view.layout=layout;
 const help=new Text(muted('F2 任务栏 · F3 工具详情 · /new 新任务 · Ctrl+C 取消退出'),1,0);
 tui.addChild(layout);bottom.addChild(state);bottom.addChild(editor);bottom.addChild(help);tui.setFocus(editor);
 function refresh() {
  const current=view.currentState;
  state.setText(paint(String(statusLabel({...current,busy:view.busy}))+' · L'+(current.level??0)+' · 任务 '+(current.task_id??'—'),{accent:true}));
  sidebar.setText(taskPanel({...current,busy:view.busy},view.details));
 }
 function note(text){if(text)transcript.addChild(new Text(text,1,0));}
 function markdown(text) {
  text=normalized(text);
  if(text&&!shown.has(text)&&![...previews.values()].some(item=>normalized(item.text)===text)) {
   transcript.addChild(new Markdown(text,1,0,theme));shown.add(text);
  }
 }
 function loading(text) {
  view.busy=true;
  if(!view.loader){bottom.removeChild(editor);bottom.removeChild(help);view.loader=new Loader(tui,accent,muted,text);bottom.addChild(view.loader);bottom.addChild(editor);bottom.addChild(help);}
  else view.loader.setMessage(text);
 }
 function idle(){view.busy=false;if(view.loader){view.loader.stop();bottom.removeChild(view.loader);view.loader=null;}}
 function toggleDetails(){view.details=!view.details;refresh();tui.requestRender();}
 editor.onSubmit=text=>{
  const draft=text;text=text.trim();if(!text)return;
  if(text==='/sidebar'||text==='/details') {
   editor.setText('');editor.addToHistory(text);
   if(text==='/sidebar')layout.toggleSidebar();else toggleDetails();
   tui.requestRender();return;
  }
  const lower=text.toLowerCase();
  const command=['status','状态','report','报告','生成报告','stop','abort','quit','exit','退出','/new'].includes(lower)||/^\/budget(?:\s|$)/i.test(text);
  if(view.busy&&!command){editor.setText(draft);state.setText('执行中；可输入 status、stop、abort、/new 或 quit');tui.requestRender();return;}
  if(view.busy&&/^\/budget(?:\s|$)/i.test(text)){editor.setText(draft);state.setText('任务暂停后可用 /budget cost USD');tui.requestRender();return;}
  editor.addToHistory(text);editor.setText('');note(paint('recon> '+text,{bold:true,accent:true}));
  if(!command)loading('等待模型…');
  send({type:'input',text});refresh();tui.requestRender();
 };
 view.handleInput=data=>{
  if(matchesKey(data,Key.f2)){layout.toggleSidebar();tui.requestRender();return {consume:true};}
  if(matchesKey(data,Key.f3)){toggleDetails();return {consume:true};}
  if((layout.sidebarVisible??terminal.columns>=100)&&(matchesKey(data,Key.pageUp)||matchesKey(data,Key.pageDown))) {
   layout.scrollSidebar(matchesKey(data,Key.pageUp)?-5:5);tui.requestRender();return {consume:true};
  }
  if(matchesKey(data,Key.ctrl('c'))){view.exitCode=130;send({type:'cancel',exit:true});loading('正在取消并保存…');refresh();tui.requestRender();return {consume:true};}
 };
 tui.addInputListener(view.handleInput);
 function toolSummary(event) {
  const result=event.result??{};
  if(event.phase==='tool_wait')return event.name+' · 执行中 '+seconds(event.elapsed_seconds)+'s / '+(event.timeout_seconds==null?'未设置上限':seconds(event.timeout_seconds)+'s');
  if(event.phase==='tool_cancelled')return event.name+' · 已取消等待'+(result.outcome_unknown?' · 副作用未知':event.result?'':' · 执行是否停止未确认');
  const status=result.status==='timeout'?'超时':result.status==='cancelled'?'已取消':result.status==='partial'?'部分完成':event.success?'完成':'异常';
  return event.name+' · '+status+(event.elapsed!=null?' · '+seconds(event.elapsed)+'s':'')+(result.outcome_unknown?' · 副作用未知':'')+(result.summary?'\n'+result.summary:result.error?'\n'+result.error:'');
 }
 function tool(event) {
  if(event.phase==='tool_late') {
   const name=event.name??tools.get(event.execution_id)?.event.name??event.result?.name??'工具';
   transcript.addChild({invalidate(){},render(width){
    const detail=view.details?'\n'+JSON.stringify({result:event.result,artifacts:event.artifacts},null,2):'';
    return new Text(muted(name+' · 迟到结果（仅诊断，不计为正常完成）')+detail,1,0).render(width);
   }});return;
  }
  const id=event.execution_id??event.name;
  let item=tools.get(id);
  if(!item) {
   item={event};item.component={invalidate(){},render(width){
    const detail=view.details&&item.event.result?'\n'+JSON.stringify(item.event.result,null,2):'';
    return new Text(toolSummary(item.event)+detail,1,0).render(width);
   }};
   tools.set(id,item);transcript.addChild(item.component);
  }
  item.event=event;
  if(event.phase==='tool_wait')loading(toolSummary(event));
  else if(view.busy&&view.loader)view.loader.setMessage(event.phase==='tool_cancelled'?'工具已取消，正在保存…':'工具已返回，任务继续执行…');
 }
 view.handle=event=>{
  switch(event.type) {
   case 'preview': {
    let item=previews.get(event.id);
    if(!item){item={markdown:new Markdown('',1,0,theme),segments:new Map()};previews.set(event.id,item);note(muted('模型回复（未验证）:'));transcript.addChild(item.markdown);}
    item.segments.set(event.offset??0,event.text);
    item.text=[...item.segments].sort((a,b)=>a[0]-b[0]).map(([,text])=>text).join('');
    item.markdown.setText(item.text);break;
   }
   case 'activity':loading(event.text);break;
   case 'context': {
    const metrics=Object.fromEntries(Object.entries(event).filter(([key])=>key.startsWith('context_')));
    view.currentState={...view.currentState,...metrics};
    if(event.context_compressed&&event.context_saved_tokens>0)view.currentState.context_last_compression={
     before:event.context_before_tokens,after:event.context_tokens,saved:event.context_saved_tokens};
    if(view.busy&&view.loader)view.loader.setMessage(event.context_limited?'上下文超限，正在保存…':
     event.context_compressed?'上下文已压缩，等待模型…':'上下文已更新，等待模型…');
    break;
   }
   case 'tool':tool(event);break;
   case 'note':note(event.text);break;
   case 'state': {
    if(event.task_id&&view.currentState.task_id&&event.task_id!==view.currentState.task_id) {
     transcript.clear();previews.clear();shown.clear();tools.clear();pendingShown=null;layout.sidebarScroll=0;view.currentState={};
    }
    view.currentState={...view.currentState,...event,pending:event.pending??null,answer:event.answer??''};
    if(event.busy)loading(view.loader?.message??'任务执行中…');else idle();
    if(event.plan)markdown('计划: '+event.plan);
    markdown(event.answer);
    if(event.pending){
     const key=JSON.stringify([event.pending.interrupt_id,event.pending.kind,event.pending.question,event.pending.options]);
     if(key!==pendingShown){
      // Prompts are interactions, not reusable answer text. A renewed prompt
      // with identical wording must remain visible after rejection/retry.
      transcript.addChild(new Markdown('等待回复 ['+event.pending.kind+']\n'+(event.pending.question??'')+'\n'+(event.pending.options??[]).join(' / '),1,0,theme));
      pendingShown=key;
     }
    }else pendingShown=null;
    break;
   }
   case 'shutdown':view.exitCode=event.code??view.exitCode;onExit(view.exitCode);break;
  }
  refresh();tui.requestRender();
 };
 const unsubscribe=tui.onTerminalColorSchemeChange(next=>{if(!automaticTheme)return;scheme=next;layout.invalidate();refresh();tui.requestRender();});
 refresh();
 view.start=()=>{
  tui.start();
  if(color&&automaticTheme)tui.setTerminalColorSchemeNotifications(true);
 };
 view.stop=()=>{idle();unsubscribe();tui.stop();};
 return view;
}
