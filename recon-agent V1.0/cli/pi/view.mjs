import {TuiMainScreen, Container, Text, Markdown, Editor, Loader, matchesKey, Key,styleText,parseColor} from '@earendil-works/pi-tui';

const plain = text => text;
const markdownTheme = Object.fromEntries(['heading','link','linkUrl','code','codeBlock','codeBlockBorder','quote','quoteBorder','hr','listBullet','bold','italic','strikethrough','underline'].map(key=>[key,plain]));
const editorTheme = {borderColor:plain,selectList:Object.fromEntries(['selectedPrefix','selectedText','description','scrollInfo','noMatch'].map(key=>[key,plain]))};

export function createView(terminal, send, onExit=()=>{}) {
 const tui=new TuiMainScreen(terminal);
 const transcript=new Container(), bottom=new Container(), state=new Text('等待任务 · L0',1,0);
 const editor=new Editor(tui,editorTheme,{paddingX:1});
 const previews=new Map(), shown=new Set();
 const color=!(process.env.NO_COLOR!==undefined||process.env.TERM==='dumb');
 const style=(text,attrs)=>color?styleText(text,attrs):text;
 const cyan=parseColor('#81c7cf'),gray=parseColor('#999999');
 const theme={...markdownTheme,heading:text=>style(text,{bold:true,fg:cyan}),bold:text=>style(text,{bold:true}),code:text=>style(text,{fg:cyan})};
 const view={tui,transcript,editor,busy:false,loader:null,exitCode:0};
 tui.addChild(transcript);tui.addChild(bottom);bottom.addChild(state);bottom.addChild(editor);tui.setFocus(editor);
 function note(text){if(text)transcript.addChild(new Text(text,1,0));}
 function markdown(text){if(text&&!shown.has(text)&&![...previews.values()].some(item=>item.text===text)){transcript.addChild(new Markdown(text,1,0,theme));shown.add(text);}}
 function loading(text){
  view.busy=true;
  if(!view.loader){bottom.removeChild(editor);view.loader=new Loader(tui,plain,plain,text);bottom.addChild(view.loader);bottom.addChild(editor);}
  else view.loader.setMessage(text);
 }
 function idle(){view.busy=false;if(view.loader){view.loader.stop();bottom.removeChild(view.loader);view.loader=null;}}
 editor.onSubmit=text=>{
  const draft=text;
  text=text.trim();if(!text)return;
  const command=['status','状态','report','报告','生成报告','stop','abort','quit','exit','退出'].includes(text.toLowerCase());
  if(view.busy&&!command){editor.setText(draft);state.setText('任务运行中；可输入 stop、abort 或 quit');tui.requestRender();return;}
  editor.addToHistory(text);editor.setText('');note(style('recon> '+text,{bold:true,fg:cyan}));
  if(!command)loading('等待模型…');
  send({type:'input',text});tui.requestRender();
 };
 view.handleInput=data=>{
  if(matchesKey(data,Key.ctrl('c'))){view.exitCode=130;send({type:'cancel',exit:true});loading('正在取消并保存…');tui.requestRender();return {consume:true};}
 };
 tui.addInputListener(view.handleInput);
 view.handle=event=>{
  switch(event.type){
   case 'preview':{
    let item=previews.get(event.id);
    if(!item){item={markdown:new Markdown('',1,0,theme),segments:new Map()};previews.set(event.id,item);note(style('模型回复（未验证）:',{fg:gray}));transcript.addChild(item.markdown);}
    item.segments.set(event.offset??0,event.text);
    const text=[...item.segments].sort((a,b)=>a[0]-b[0]).map(([,text])=>text).join('');
    item.text=text;item.markdown.setText(text);break;
   }
   case 'activity':loading(event.text);break;
   case 'note':note(event.text);break;
   case 'state':
    if(event.busy)loading('任务执行中…');else idle();state.setText(`状态: ${event.status} · L${event.level} · tokens ${event.used_tokens??0}`);
    if(event.plan)markdown('计划: '+event.plan);
    markdown(event.answer);
    if(event.pending){note(`等待回复 [${event.pending.kind}]`);markdown(event.pending.question);note((event.pending.options??[]).join(' / '));}
    break;
   case 'shutdown':view.exitCode=event.code??view.exitCode;onExit(view.exitCode);break;
  }
  tui.requestRender();
 };
 view.start=()=>tui.start();
 view.stop=()=>{idle();tui.stop();};
 return view;
}
