import {ProcessTerminal} from '@earendil-works/pi-tui';
import {connectBridge} from './bridge.mjs';
import {createSetupView} from './setup.mjs';

let bridge,view,finished=false;
function finish(code=0){
 if(finished)return;finished=true;
 view?.stop();bridge?.close();process.exitCode=code;process.stdin.pause();
}
try{
 view=createSetupView(new ProcessTerminal(),command=>bridge.send(command),finish);
 bridge=await connectBridge({onEvent:event=>view.handle(event),onClose:()=>finish(view.closed?view.exitCode:2)});
 delete process.env.RECON_TUI_TOKEN;
 view.start();
 process.on('SIGINT',()=>{view.form.handleInput('\x03');});
 process.on('SIGTERM',()=>{view.form.handleInput('\x03');finish(130);});
 process.on('uncaughtException',()=>finish(2));
 process.on('unhandledRejection',()=>finish(2));
}catch{finish(2);}
