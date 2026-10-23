import {Text, truncateToWidth, visibleWidth} from '@earendil-works/pi-tui';

// One conversation column at every terminal width.
export class ConversationLayout {
 constructor(transcript,bottom,paint,clean=text=>text) {Object.assign(this,{transcript,bottom,paint,clean});}
 invalidate() {this.transcript.invalidate();this.bottom.invalidate();}
 render(width) {
  width=Math.max(1,width);
  return [...this.transcript.render(width),...this.bottom.render(width)]
   .map(line=>this.clean(truncateToWidth(line,width,'')));
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

const number=value=>value==null?'未知':Number(value).toLocaleString('en-US');
export function costLabel(state) {
 return state.used_cost==null?'费用未知':'$'+Number(state.used_cost).toFixed(4)+(state.cost_unknown_calls>0?' + 未知':'');
}
export function compactStatus(state,width) {
 let text=statusLabel(state);
 const model=state.model?'模型 '+state.model:'';
 if(model&&visibleWidth(text+' · '+model)<=Math.max(1,width-2)){
  text+=' · '+model;
 }
 return text;
}

const compactNumber=value=>value==null?'未知':value>=1000000?Number((value/1000000).toFixed(1))+'m':
 value>=1000?Number((value/1000).toFixed(1))+'k':String(value);

// Align metadata below the editor using terminal columns, not string length.
export function inputFooter(state,width,paint=text=>text) {
 width=Math.max(1,width);
 const model=state.model?'模型 '+state.model:'模型未知';
 if(width<10)return paint(truncateToWidth(model,width,'…'),{accent:true});
 const inner=width-2,gap=2,minModel=Math.min(12,Math.floor(inner/3));
 const rightWidth=inner-minModel-gap;
 const used=state.context_tokens,capacity=state.context_capacity>0?state.context_capacity:null;
 const ratio=used!=null&&capacity!=null?Math.round(used/capacity*100)+'%':'未知';
 const threshold=capacity!=null&&state.context_trigger_tokens>0?
  Math.round(state.context_trigger_tokens/capacity*100)+'%':null;
 const estimate=state.context_estimated?'≈':'';
 const count=state.context_compactions??0;
 const compression=state.context_limited?'上下文超限':count>0?'已压缩 '+number(count)+' 次':
  threshold?threshold+' 自动压缩':'';
 const shortCompression=state.context_limited?'超限':count>0?'已压缩'+compactNumber(count)+'次':
  threshold?threshold+'压缩':'';
 const saved=state.context_last_compression?.saved??state.context_saved_tokens;
 const fullCompression=compression+(count>0&&saved>0?' · 节省 '+number(saved):'');
 const full=estimate+number(used)+' / '+number(capacity)+' tokens · '+ratio;
 const compact=estimate+compactNumber(used)+' tokens · '+ratio;
 const variants=used==null?['上下文未知']:[
  full+(fullCompression?' · '+fullCompression:''),
  full+(compression?' · '+compression:''),
  compact+(shortCompression?' · '+shortCompression:''),
  compact,estimate+compactNumber(used)+' tokens',ratio,
 ];
 const right=truncateToWidth(variants.find(text=>visibleWidth(text)<=rightWidth)??variants.at(-1),rightWidth,'…');
 const left=truncateToWidth(model,inner-visibleWidth(right)-gap,'…');
 return ' '+paint(left,{accent:true})+' '.repeat(inner-visibleWidth(left)-visibleWidth(right))+
  paint(right,state.context_limited?{warning:true}:{muted:true})+' ';
}

export function taskStatus(state) {
 const lines=['状态（最新）','任务 · '+(state.task_id||'尚未创建'),statusLabel(state)+' · L'+(state.level??0),
  '模型 · '+(state.model||'未知'),'上下文',(state.context_estimated?'估算 ':'')+number(state.context_tokens)+' / '+number(state.context_capacity)+' tokens',
  '压缩触发 '+number(state.context_trigger_tokens)+' tokens · 累计压缩 '+number(state.context_compactions)+' 次'];
 const last=state.context_last_compression??(state.context_saved_tokens>0?{
  before:state.context_before_tokens,after:state.context_tokens,saved:state.context_saved_tokens}:null);
 if(last)lines.push('上次压缩 '+number(last.before)+' → '+number(last.after)+' · 节省 '+number(last.saved)+' tokens');
 lines.push('预算',costLabel(state)+' / '+(state.max_cost==null?'上限未知':'$'+state.max_cost),
  '累计 tokens '+number(state.used_tokens)+' · 决策 '+number(state.decisions)+' · 动作 '+number(state.actions),
  '计划',state.plan||'等待计划','最近工具');
 if(state.pending)lines.splice(lines.length-1,0,'待回复 · '+state.pending.kind,state.pending.question||'问题已在对话中展示',(state.pending.options??[]).join(' / '));
 const results=state.results??[];
 for(const result of results)lines.push((result.name??'工具')+' · '+(result.status??'未知'),result.summary||result.error||'');
 if(!results.length)lines.push('暂无结果');
 lines.push('证据');
 const evidence=results.flatMap(result=>result.evidence??[]);
 lines.push(...(evidence.length?evidence.map(value=>typeof value==='string'?value:JSON.stringify(value)):['暂无证据']));
 lines.push('产物');
 const artifacts=results.flatMap(result=>result.artifacts??[]);
 lines.push(...(artifacts.length?artifacts.map(a=>(a.purpose||a.id||'产物')+' · '+(a.path||'路径未提供')):['暂无产物']));
 return lines.join('\n');
}
