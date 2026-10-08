import net from 'node:net';
import {StringDecoder} from 'node:string_decoder';

export async function connectBridge({port=process.env.RECON_PI_PORT,token=process.env.RECON_PI_TOKEN,onEvent,onClose}){
 const socket=net.createConnection({host:'127.0.0.1',port:Number(port)});
 const decoder=new StringDecoder('utf8');let pending='', closed=false;
 const close=()=>{if(!closed){closed=true;onClose?.();}};
 socket.on('error',close);socket.on('close',close);
 socket.on('data',data=>{
  pending+=decoder.write(data);
  if(Buffer.byteLength(pending)>131072){socket.destroy();return;}
  let index;
  while((index=pending.indexOf('\n'))>=0){
   const line=pending.slice(0,index);pending=pending.slice(index+1);
   try{if(Buffer.byteLength(line)>65536)throw new Error('frame too large');onEvent(JSON.parse(line));}
   catch{socket.destroy();return;}
  }
 });
 await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});
 function send(command){
  if(closed)return;
  const frame=JSON.stringify(command)+'\n';
  if(Buffer.byteLength(frame)>65536||socket.writableLength>65536){socket.destroy();return;}
  socket.write(frame);
 }
 send({type:'hello',token});
 return {send,close:()=>socket.end(),destroy:()=>socket.destroy()};
}
