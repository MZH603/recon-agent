import {Text, truncateToWidth} from '@earendil-works/pi-tui';

// Keep the panel beside the visible tail, even when replies fill scrollback.
export class TaskLayout {
 constructor(terminal,transcript,bottom,sidebar,paint,clean=text=>text) {
  Object.assign(this,{terminal,transcript,bottom,sidebar,paint,clean});
  this.sidebarVisible=undefined;this.sidebarScroll=0;
 }
 toggleSidebar(width=this.terminal.columns) {
  this.sidebarVisible=!(this.sidebarVisible??width>=100);this.sidebarScroll=0;
 }
 scrollSidebar(delta) {this.sidebarScroll=Math.max(0,this.sidebarScroll+delta);}
 invalidate() {this.transcript.invalidate();this.bottom.invalidate();this.sidebar.invalidate();}
 render(width) {
  width=Math.max(1,width);
  const show=this.sidebarVisible??width>=100,wide=show&&width>=100;
  const panelWidth=wide?Math.min(40,Math.floor(width/3)):width;
  const mainWidth=wide?width-panelWidth-3:width;
  const bottom=this.bottom.render(mainWidth),transcript=this.transcript.render(mainWidth);
  const heading=new Text(this.paint('RECON · 对话',{bold:true,accent:true}),1,0).render(mainWidth);
  const left=[...heading,...transcript,...bottom].map(line=>truncateToWidth(line,mainWidth,''));
  if(!show)return left.map(this.clean);
  const panel=this.sidebar.render(panelWidth).map(line=>truncateToWidth(line,panelWidth,''));
  const available=Math.max(3,(this.terminal.rows??24)-(wide?1:bottom.length+2));
  const overflow=panel.length>available,count=overflow?available-1:available;
  this.sidebarScroll=Math.min(this.sidebarScroll,Math.max(0,panel.length-count));
  const visible=panel.slice(this.sidebarScroll,this.sidebarScroll+count);
  if(overflow)visible.push(...new Text(`PgUp/PgDn · ${this.sidebarScroll+1}–${this.sidebarScroll+visible.length}/${panel.length}`,0,0).render(panelWidth).slice(0,1));
  if(!wide)return [...heading,...transcript,this.paint('─'.repeat(width),{muted:true}),...visible,...bottom].map(line=>this.clean(truncateToWidth(line,width,'')));
  const total=Math.max(left.length,visible.length),offset=Math.max(0,total-(this.terminal.rows??24)+1);
  const separator=this.paint(' │ ',{muted:true});
  return Array.from({length:total},(_,i)=>this.clean(truncateToWidth(left[i]??'',mainWidth,'',true)+separator+truncateToWidth(visible[i-offset]??'',panelWidth,'',true)));
 }
}

export function statusLabel(state={}) {
 if(state.busy||state.status==='running')return '执行中';
 if(state.pending) {
  const kind=state.pending.kind??'';
  if(kind==='context_limit')return '上下文超限';
  if(/budget/.test(kind))return '等待费用预算';
  if(kind==='limit')return '达到限制';
  if(/approval|authoriz|permission|confirm/.test(kind)||['l1','l2_unlock','l2_action'].includes(kind))return '等待授权';
  if(/error|conflict|uncertain|model_unavailable|schema|recovery/.test(kind))return '异常待处理';
  return '等待输入';
 }
 return ({idle:'等待任务',paused:'等待输入',finished:'已完成',completed:'已完成',done:'已完成',
  stopped:'已停止',cancelled:'已停止',aborted:'已停止',error:'异常',failed:'异常',budget:'等待费用预算',context_limit:'上下文超限'})[state.status]??'等待任务';
}

const number=value=>Number(value??0).toLocaleString('en-US');
const readable=value=>typeof value==='string'?value:JSON.stringify(value);
export function taskPanel(state,details=false) {
 const contextRatio=state.context_tokens!=null&&state.context_capacity>0?state.context_tokens/state.context_capacity:null;
 const contextUsage=state.context_tokens==null?'未知':number(state.context_tokens);
 const contextCapacity=state.context_capacity>0?number(state.context_capacity):'未知';
 const trigger=state.context_trigger_tokens==null?'未知':number(state.context_trigger_tokens);
 const last=state.context_last_compression??(state.context_saved_tokens>0?{
  before:state.context_before_tokens,after:state.context_before_tokens-state.context_saved_tokens,saved:state.context_saved_tokens}:null);
 const lines=['任务 · '+(state.task_id??'尚未创建'),statusLabel(state)+` · L${state.level??0}`,'',
  '上下文',`${state.context_estimated?'估算 ':''}${contextUsage} / ${contextCapacity} tokens${contextRatio==null?'':` · ${Math.round(contextRatio*100)}%`}`,
  `压缩触发 ${trigger} tokens`,
  `累计压缩 ${number(state.context_compactions)} 次`];
 if(last)lines.push(`上次压缩 ${number(last.before)} → ${number(last.after)}`,`节省 ${number(last.saved)} tokens`);
 if(state.context_limited)lines.push('上下文超限 · 请调整必需内容');
 lines.push('','计划',state.plan||'等待计划');
 const results=state.results??[];
 if(results.length)lines.push('','最近工具');
 for(const result of results.slice(-10)) {
  const status=({success:'完成',failure:'异常',timeout:'超时',cancelled:'已取消',partial:'部分完成',running:'执行中'})[result.status]??'未知';
  lines.push(`${result.name??'工具'} · ${status}`,result.summary||result.error||'');
  if(details&&result.error)lines.push('错误: '+result.error);
 }
 const evidence=results.flatMap(result=>result.evidence??[]);
 if(evidence.length)lines.push('','证据',...evidence.map(readable));
 const artifacts=results.flatMap(result=>result.artifacts??[]);
 if(artifacts.length) {
  lines.push('','产物');
  for(const artifact of artifacts)lines.push(artifact.purpose||artifact.id||'产物',artifact.path||'路径未提供');
 }
 return lines.join('\n');
}
