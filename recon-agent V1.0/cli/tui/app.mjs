import {ProcessTerminal} from '@earendil-works/pi-tui';
import {connectBridge} from './bridge.mjs';
import {createView} from './view.mjs';

let bridge,view,finished=false;
function finish(code=0){
 if(finished)return;finished=true;
 view?.stop();bridge?.close();process.exitCode=code;
 process.stdin.pause();
}
try{
 view=createView(new ProcessTerminal(),command=>bridge.send(command),finish);
 bridge=await connectBridge({onEvent:event=>view.handle(event),onClose:()=>finish(view.exitCode)});
 delete process.env.RECON_TUI_TOKEN;
 view.start();
 process.on('SIGINT',()=>{bridge.send({type:'cancel',exit:true});view.exitCode=130;});
 process.on('SIGTERM',()=>{bridge.send({type:'cancel',exit:true});finish(130);});
 process.on('uncaughtException',()=>finish(2));
 process.on('unhandledRejection',()=>finish(2));
}catch{finish(2);}
