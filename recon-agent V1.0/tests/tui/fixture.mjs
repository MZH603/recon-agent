// Offline cross-language verification only; excluded from wheel package data.
import {createView} from '../../cli/tui/view.mjs';
import {connectBridge} from '../../cli/tui/bridge.mjs';
class Terminal {
 columns=50;rows=20;frames=[];stopped=false;
 start(input,resize){this.input=input;} stop(){this.stopped=true;}
 write(text){this.frames.push(text);} hideCursor(){}showCursor(){}clearLine(){}moveBy(){}clearFromCursor(){}
}
let bridge,submitted=false,loader=false,first=false,firstRendered=false,incremental=false;
const terminal=new Terminal();
const view=createView(terminal,command=>bridge.send(command));
bridge=await connectBridge({onEvent:event=>{
 view.handle(event);
 if(event.type==='state'&&!submitted){submitted=true;view.editor.onSubmit('inspect');loader=Boolean(view.loader);}
 if(event.type==='preview'){
  if(event.text.includes('首段中文😀')&&!event.text.includes('后段增量')){
   first=true;view.tui.renderNow();firstRendered=terminal.frames.join('').includes('首段中文😀');
  }
  if(first&&event.text.includes('后段增量')){incremental=true;view.tui.renderNow();bridge.destroy();}
 }
},onClose:()=>{view.stop();console.log(JSON.stringify({firstRendered,incremental,loader,restored:terminal.stopped}));}});
view.start();
