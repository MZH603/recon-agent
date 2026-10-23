import {TuiMainScreen,Container,Text,Markdown,Editor,matchesKey,Key,styleText,parseColor,getTerminalColorMode} from '@earendil-works/pi-tui';
import {ConversationLayout,compactStatus,inputFooter,taskStatus,statusLabel} from './layout.mjs';
import {slashProvider,parseCommand,helpText} from './commands.mjs';

const plain=text=>text;
const markdownKeys=['heading','link','linkUrl','code','codeBlock','codeBlockBorder','quote','quoteBorder','hr','listBullet','bold','italic','strikethrough','underline'];
const normalized=text=>String(text??'').trimEnd();
const seconds=value=>Number(value??0).toFixed(1).replace(/\.0$/,'');
const spinnerFrames=['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];

export function createView(terminal,send,onExit=()=>{},options={}) {
 const tui=new TuiMainScreen(terminal),transcript=new Container(),bottom=new Container();
 const requestedTheme=options.theme??process.env.RECON_TUI_THEME??process.env.RECON_THEME;
 const automaticTheme=!['light','dark'].includes(requestedTheme);
 let scheme=automaticTheme?(process.env.COLORFGBG?.split(';').at(-1)==='15'?'light':'dark'):requestedTheme;
 const color=options.color??!(process.env.NO_COLOR!==undefined||process.env.TERM==='dumb');
 const terminalWrite=terminal.write;
 // pi-tui appends SGR resets itself; strip those too when NO_COLOR is set.
 if(!color)terminal.write=data=>terminalWrite.call(terminal,data.replace(/\x1b\[[0-9;:]*m/g,''));
 const palette={
  light:{error:'#a62222',warning:'#856300',accent:'#006c78',muted:'#59666a',success:'#15803d',info:'#0284c7',purple:'#7e22ce',highlight:'#0f172a',dim:'#94a3b8'},
  dark:{error:'#f08080',warning:'#e7c46a',accent:'#81c7cf',muted:'#939fa2',success:'#4ade80',info:'#38bdf8',purple:'#c084fc',highlight:'#ffffff',dim:'#475569'}
 };
 const paint=(text,attrs={})=>{
  if(!color)return text;
  const p=palette[scheme==='light'?'light':'dark'];
  const fg=attrs.error?p.error:attrs.warning?p.warning:attrs.accent?p.accent:attrs.success?p.success:
   attrs.info?p.info:attrs.purple?p.purple:attrs.highlight?p.highlight:attrs.dim?p.dim:attrs.muted?p.muted:undefined;
  return styleText(text,{bold:Boolean(attrs.bold),underline:Boolean(attrs.underline),fg:fg?parseColor(fg):undefined},getTerminalColorMode());
 };
 const accent=text=>paint(text,{accent:true}),muted=text=>paint(text,{muted:true});
 const success=text=>paint(text,{success:true}),info=text=>paint(text,{info:true}),purple=text=>paint(text,{purple:true});
 const theme=Object.fromEntries(markdownKeys.map(key=>[key,plain]));
 Object.assign(theme,{
  heading:text=>paint(text,{bold:true,accent:true}),
  bold:text=>paint(text,{bold:true,highlight:true}),
  code:accent,
  codeBlock:text=>paint(text,{highlight:true}),
  codeBlockBorder:text=>paint(text,{dim:true}),
  quote:text=>paint(text,{muted:true}),
  quoteBorder:text=>paint(text,{accent:true}),
  listBullet:()=>paint('•',{accent:true}),
  link:text=>paint(text,{info:true,underline:true}),
  hr:()=>paint('─'.repeat(40),{dim:true}),
 });
 const editorTheme={borderColor:accent,selectList:{selectedPrefix:accent,selectedText:accent,description:muted,scrollInfo:muted,noMatch:muted}};
 const editor=new Editor(tui,editorTheme,{paddingX:1,autocompleteMaxVisible:9});
 editor.setAutocompleteProvider(slashProvider);
 const previews=new Map(),shown=new Set(),tools=new Map();
 let pendingShown=null,statusRequests=0,activity='';
 let started=false,animationTimer=null,spinnerIndex=0;
 const view={tui,transcript,editor,busy:false,exitCode:0,currentState:{status:'idle'}};
 // Plain content is painted at render time so existing text follows theme changes.
 function dynamic(text,attrs={}) {
  return {invalidate(){},render(width){const value=typeof text==='function'?text(width):text;return value?new Text(paint(value,attrs),1,0).render(width):[];}};
 }
 const state={invalidate(){},render(width){
  const label=statusLabel({...view.currentState,busy:view.busy});
  const text=compactStatus({...view.currentState,busy:view.busy},width);
  const isErr=/异常/.test(label),isWarn=/超限|预算|限制|授权/.test(label),isBusy=view.busy||/执行中/.test(label);
  const attr=isErr?{error:true,bold:true}:isWarn?{warning:true,bold:true}:isBusy?{info:true,bold:true}:{accent:true};
  return new Text(paint(text,attr),1,0).render(width).slice(0,1);
 }};
 const hint=dynamic(()=>/^\/budget(?:\s|$)/i.test(editor.getText())?'用法: /budget cost USD · 例如 /budget cost 1':'',{muted:true});
 const footer={invalidate(){},render(width){return [inputFooter(view.currentState,width,paint)];}};
 const live={invalidate(){},render(width){return activity?new Text(muted(spinnerFrames[spinnerIndex]+' '+activity),1,0).render(width).slice(0,1):[];}};
 const layout=new ConversationLayout(transcript,bottom,paint,text=>color?text:text.replace(/\x1b\[[0-9;:]*m/g,''));
 view.layout=layout;tui.addChild(layout);bottom.addChild(state);bottom.addChild(live);bottom.addChild(editor);bottom.addChild(footer);bottom.addChild(hint);tui.setFocus(editor);
 function note(text,attrs={}){if(text)transcript.addChild(dynamic(text,attrs));}
 function markdown(text) {
  text=normalized(text);
  if(text&&!shown.has(text)&&![...previews.values()].some(item=>normalized(item.text)===text)) {
   transcript.addChild(new Markdown(text,1,0,theme));shown.add(text);
  }
 }
 function syncAnimation() {
  if(started&&view.busy) {
   if(animationTimer===null)animationTimer=setInterval(()=>{
    spinnerIndex=(spinnerIndex+1)%spinnerFrames.length;
    tui.requestRender();
   },100);
  }else if(animationTimer!==null){clearInterval(animationTimer);animationTimer=null;}
 }
 function loading(text){view.busy=true;if(text)activity=text;syncAnimation();}
 function idle(){view.busy=false;activity='';syncAnimation();}
 function details() {
  note('最近工具详情（桥接传输已限长；完整证据请查看产物）',{muted:true});
  if(!tools.size)note('暂无工具结果。',{muted:true});
  for(const item of [...tools.values()].slice(-5))note(JSON.stringify(item.event,null,2),{muted:true});
 }
 editor.onChange=()=>tui.requestRender();
 editor.onSubmit=text=>{
  const draft=text;text=text.trim();if(!text)return;
  const command=parseCommand(text);
  if(command?.error){editor.setText(draft);note(command.error,{warning:true});tui.requestRender();return;}
  if(view.busy&&(!command||command.name==='budget')) {
   editor.setText(draft);note(command?.name==='budget'?'任务暂停后可用 /budget cost USD。':'任务执行中，草稿已保留；可用 /status、/stop、/abort。',{warning:true});
   tui.requestRender();return;
  }
  editor.addToHistory(text);editor.setText('');note(paint('❯ ',{bold:true,accent:true})+paint(text,{bold:true,highlight:true}));
  if(command?.name==='help')note(helpText,{muted:true});
  else if(command?.name==='details')details();
  else if(command?.name==='status'){statusRequests++;send({type:'status'});}
  else if(command&&['report','stop','abort','quit'].includes(command.name))send({type:command.name});
  else {
   if(!command)loading('等待模型…');
   send({type:'input',text:command?.name==='new'?'/new':text});
  }
  tui.requestRender();
 };
 view.handleInput=data=>{
  if(matchesKey(data,Key.ctrl('c'))){view.exitCode=130;send({type:'cancel',exit:true});loading('正在取消并保存…');tui.requestRender();return {consume:true};}
 };
 tui.addInputListener(view.handleInput);
 function toolHeader(event,withSpinner=true) {
  const result=event.result??{};
  if(event.phase==='tool_late')return (event.name??'工具')+' · 迟到结果（仅诊断，不计为正常完成）';
  let status,glyph;
  if(event.phase==='tool_start'){status='开始执行';glyph=withSpinner?spinnerFrames[spinnerIndex]+' ':'';}
  else if(event.phase==='tool_wait'){status='执行中 '+seconds(event.elapsed_seconds)+'s'+(event.timeout_seconds==null?'':' / '+seconds(event.timeout_seconds)+'s');glyph=withSpinner?spinnerFrames[spinnerIndex]+' ':'';}
  else if(event.phase==='tool_cancelled'){status='已取消等待';glyph='⊘ ';}
  else {
   const outcome=result.status??(event.success?'success':'failure');
   status=({timeout:'超时',cancelled:'已取消',partial:'部分完成',success:'完成',failure:'异常'})[outcome]??(event.success?'完成':'异常');
   glyph=outcome==='success'?'✓ ':outcome==='timeout'?'⏱ ':outcome==='failure'?'✗ ':'⚠️ ';
  }
  return glyph+(event.name??'工具')+' · '+status+(event.elapsed!=null?' · '+seconds(event.elapsed)+'s':'')+
   (result.outcome_unknown?' · 副作用未知':event.phase==='tool_cancelled'?' · 执行是否停止未确认':'');
 }
 function toolComponent(item) {
  return {invalidate(){},render(width){
   const event=item.event,result=event.result??{};
   const header=toolHeader(event);
   const problem=/异常|✗/.test(header);
   const warning=/超时|取消|部分|未知|迟到|⚠️|⏱/.test(header);
   const isSuccess=/完成|✓/.test(header);
   const isActive=/开始|执行中|⠋|⠹/.test(header);
   const headerAttr=problem?{error:true,bold:true}:
    warning?{warning:true,bold:true}:
    isSuccess?{success:true,bold:true}:
    isActive?{info:true,bold:true}:{muted:true};
   const lines=new Text(paint(header,headerAttr),1,0).render(width);
   if(event.arguments&&Object.keys(event.arguments).length) {
    const args=new Text(muted('  参数: '+JSON.stringify(event.arguments)),1,0).render(width);
    lines.push(...args.slice(0,2));
    if(args.length>2)lines.push(...new Text(muted('  …参数已截断；/details 查看'),1,0).render(width));
   }
   const summary=result.error&&(!event.success||result.status!=='success')?
    result.error+(result.summary?'\n'+result.summary:''):result.summary||result.error||'';
   const wrapped=summary?new Text(muted(summary),1,0).render(width):[];
   lines.push(...wrapped.slice(0,3));
   if(wrapped.length>3)lines.push(...new Text(muted('  …摘要已截断；/details 查看桥接详情'),1,0).render(width));
   return lines;
  }};
 }
 function tool(event) {
  const id=event.execution_id??event.name;
  if(event.phase==='tool_late') {
   const late={event:{...tools.get(id)?.event,...event}};
   // Late diagnostics never replace the durable normal outcome.
   tools.set(id+':late',late);transcript.addChild(toolComponent(late));return;
  }
  let item=tools.get(id);
  if(!item){item={event:{}};tools.set(id,item);transcript.addChild(toolComponent(item));}
  item.event={...item.event,...event};
  if(event.phase==='tool_start'||event.phase==='tool_wait')loading(toolHeader(event,false));
  else if(view.busy)activity=event.phase==='tool_cancelled'?'工具已取消，正在保存…':'工具已返回，继续处理…';
 }
 view.handle=event=>{
  switch(event.type) {
   case 'preview': {
    let item=previews.get(event.id);
    if(!item){
     item={markdown:new Markdown('',1,0,theme),segments:new Map()};
     previews.set(event.id,item);
     note(paint('✦ Recon Agent',{bold:true,purple:true})+paint(' · 回复生成中',{muted:true}));
     transcript.addChild(item.markdown);
    }
    item.segments.set(event.offset??0,event.text);
    item.text=[...item.segments].sort((a,b)=>a[0]-b[0]).map(([,text])=>text).join('');item.markdown.setText(item.text);break;
   }
   case 'activity':
    if(event.model)view.currentState.model=event.model;
    loading(event.text);break;
   case 'context': {
    const metrics=Object.fromEntries(Object.entries(event).filter(([key])=>key.startsWith('context_')));
    view.currentState={...view.currentState,...metrics};
    if(event.context_compressed&&event.context_saved_tokens>0)view.currentState.context_last_compression={before:event.context_before_tokens,after:event.context_tokens,saved:event.context_saved_tokens};
    if(view.busy)activity=event.context_limited?'上下文超限，正在保存…':event.context_compressed?'上下文已压缩，等待模型…':'上下文已更新，等待模型…';
    break;
   }
   case 'tool':tool(event);break;
   case 'note':note(event.text);break;
   case 'state': {
    if(event.task_id&&view.currentState.task_id&&event.task_id!==view.currentState.task_id) {
     transcript.clear();previews.clear();shown.clear();tools.clear();pendingShown=null;view.currentState={};
    }
    view.currentState={...view.currentState,...event,pending:event.pending??null,answer:event.answer??''};
    if(event.busy||event.status==='running')loading();else idle();
    if(statusRequests>0&&event.status_requested){statusRequests--;note(taskStatus(event),{muted:true});}
    else if(event.plan)markdown('计划: '+event.plan);
    markdown(event.answer);
    if(event.pending){
     const key=JSON.stringify([event.pending.interrupt_id,event.pending.kind,event.pending.question,event.pending.options]);
     if(key!==pendingShown){
      const title=paint('? 等待确认 ['+event.pending.kind+']',{bold:true,warning:true});
      const q=event.pending.question?paint(event.pending.question,{bold:true,highlight:true}):'';
      const opts=(event.pending.options??[]).map(opt=>paint('['+opt+']',{accent:true,bold:true})).join('  ');
      transcript.addChild(new Markdown(title+(q?'\n'+q:'')+(opts?'\n'+opts:''),1,0,theme));
      pendingShown=key;
     }
    }else pendingShown=null;
    break;
   }
   case 'shutdown':idle();view.exitCode=event.code??view.exitCode;onExit(view.exitCode);break;
  }
  tui.requestRender();
 };
 const unsubscribe=tui.onTerminalColorSchemeChange(next=>{if(!automaticTheme)return;scheme=next;layout.invalidate();tui.requestRender();});
 view.start=()=>{tui.start();started=true;syncAnimation();if(color&&automaticTheme)tui.setTerminalColorSchemeNotifications(true);};
 view.stop=()=>{started=false;idle();unsubscribe();tui.stop();terminal.write=terminalWrite;};
 return view;
}
