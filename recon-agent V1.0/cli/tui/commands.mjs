export const commands=[
 ['new','开启新任务'],['status','查看最新任务、计划、预算与证据'],['report','生成当前任务报告'],
 ['budget','追加费用预算 · cost USD'],['stop','停止执行并保存进度'],['abort','中止当前任务'],
 ['help','显示命令与按键帮助'],['details','查看最近工具的桥接详情'],['quit','保存并退出'],
].map(([name,description])=>({value:'/'+name,label:'/'+name,description}));

// Slash commands only: normal prose and Tab never discover local files.
export const slashProvider={
 triggerCharacters:['/'],
 async getSuggestions(lines,line,col) {
  if(line!==0||lines.length!==1)return null;
  const prefix=lines[0].slice(0,col);
  if(!/^\/[a-z]*$/i.test(prefix))return null;
  const items=commands.filter(item=>item.value.startsWith(prefix.toLowerCase()));
  return items.length?{items,prefix}:null;
 },
 applyCompletion(lines,line,col,item,prefix) {
  const value=item.value==='/budget'?'/budget cost ':item.value;
  return {lines:[value+lines[0].slice(col)],cursorLine:0,cursorCol:value.length};
 },
 shouldTriggerFileCompletion(){return false;},
};

const aliases={status:'status','状态':'status',report:'report','报告':'report','生成报告':'report',
 stop:'stop',abort:'abort',quit:'quit',exit:'quit','退出':'quit',new:'new'};
export function parseCommand(text) {
 const parts=text.split(/\s+/),head=parts[0].toLowerCase();
 if(!head.startsWith('/'))return aliases[text.toLowerCase()]?{name:aliases[text.toLowerCase()]}:null;
 const name=head.slice(1);
 if(!commands.some(item=>item.value===head))return {error:'未知命令；输入 / 查看可用命令。'};
 if(name==='budget') {
  if(parts.length!==3||parts[1].toLowerCase()!=='cost')return {error:'用法: /budget cost USD，例如 /budget cost 1'};
  if(!/^[+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(parts[2]))return {error:'追加费用必须为有限正数（USD）'};
  const cost=Number(parts[2]);
  if(!Number.isFinite(cost)||cost<=0)return {error:'追加费用必须为有限正数（USD）'};
 }else if(parts.length!==1)return {error:'/'+name+' 不接受参数。'};
 return {name};
}
export const helpText=commands.map(item=>item.value+(item.value==='/budget'?' cost USD':'')+' · '+item.description).join('\n')+
 '\n↑/↓ 选择命令 · Tab 补全 · Esc 关闭菜单\nEnter 发送 · Shift+Enter 换行 · ↑/↓ 输入历史 · Ctrl+C 取消并退出';
