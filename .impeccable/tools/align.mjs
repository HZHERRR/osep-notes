#!/usr/bin/env node
// Report the left/right edges of the elements that are supposed to share an edge.
import { spawn } from 'node:child_process'
const CHROME='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const PORT=9340, sleep=ms=>new Promise(r=>setTimeout(r,ms))
const urls = process.argv.slice(2)
const chrome=spawn(CHROME,['--headless=new','--disable-gpu','--hide-scrollbars','--no-first-run',`--remote-debugging-port=${PORT}`,'--user-data-dir=/tmp/cdp-align','about:blank'],{stdio:'ignore'})
let id=0; const pending=new Map(); let ws
const send=(m,p={})=>{const i=++id; ws.send(JSON.stringify({id:i,method:m,params:p})); return new Promise((res,rej)=>pending.set(i,{res,rej}))}
const ev=async e=>(await send('Runtime.evaluate',{expression:e,awaitPromise:true,returnByValue:true})).result?.value
try{
  for(let i=0;i<60;i++){try{if((await fetch(`http://127.0.0.1:${PORT}/json/version`)).ok)break}catch{}await sleep(250)}
  const t=await(await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`,{method:'PUT'})).json()
  ws=new WebSocket(t.webSocketDebuggerUrl)
  ws.addEventListener('message',e=>{const m=JSON.parse(e.data); if(m.id&&pending.has(m.id)){const{res,rej}=pending.get(m.id);pending.delete(m.id);m.error?rej(new Error(JSON.stringify(m.error))):res(m.result)}})
  await new Promise(r=>ws.addEventListener('open',r,{once:true}))
  await send('Page.enable'); await send('Runtime.enable')
  await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]})
  for (const url of urls) {
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false})
    await send('Page.navigate',{url}); await sleep(2800)
    const out = await ev(`(()=>{
      const sels=['.vp-doc h1','.vp-doc h2','.vp-doc p','.vp-doc ul','.vp-doc blockquote','.vp-doc .table-scroll','.vp-doc div[class*="language-"]','.vp-doc div.custom-block','.VPDoc .content-container','.VPDocAsideOutline .outline-link','.storm-title','.storm-lede','.storm-actions','.storm-index','.storm-front-name','.storm-front-condition','.storm-entries','.storm-boundary p'];
      const rows=[];
      for (const s of sels) {
        const el=document.querySelector(s); if(!el) continue;
        const r=el.getBoundingClientRect();
        rows.push(s.padEnd(36)+' L='+Math.round(r.left).toString().padStart(5)+' R='+Math.round(r.right).toString().padStart(5)+' W='+Math.round(r.width).toString().padStart(5));
      }
      return rows.join('\\n');
    })()`)
    console.log('===== '+url)
    console.log(out)
  }
} finally { chrome.kill('SIGKILL') }
