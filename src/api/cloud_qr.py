<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>iCourse 云端扫码</title><style>body{font:18px system-ui;max-width:650px;margin:50px auto;padding:20px}input,button{font:inherit;margin:8px;padding:10px}img{display:block;width:300px;max-width:100%}</style><h1>验证正在运行的 GitHub 任务</h1><p>学号、密码仅在本浏览器解密二维码，不向服务器发送。请用微信扫码并确认。输入框在解密后会自动清空，这是正常行为。</p><form id="form"><input id="student" placeholder="学号" autocomplete="username" required><input id="password" type="password" placeholder="学校密码" autocomplete="current-password" required><button>显示二维码</button></form><p id="status">请从正在运行的任务摘要打开本页。</p><img id="qr" hidden alt="学校二次认证二维码"><script>
const run=new URLSearchParams(location.search).get('run'),owner=location.hostname.split('.')[0],repo=location.pathname.split('/').filter(Boolean)[0];
let timer,busy=false,credentials,nextApiAt=0,apiNotice="";
const status=document.getElementById('status'),img=document.getElementById('qr');
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function update(){if(busy||!credentials)return;busy=true;try{
async function decode(envelope){if(envelope.run!==run||envelope.version!==1)throw Error('任务标识不匹配');
const raw=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('ICS-QR-v1:'+credentials.student+':'+credentials.password));
const base=await crypto.subtle.importKey('raw',raw,'PBKDF2',false,['deriveKey']);
const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes(envelope.salt),iterations:200000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
const c=bytes(envelope.ciphertext),tag=bytes(envelope.tag),joined=new Uint8Array(c.length+tag.length);joined.set(c);joined.set(tag,c.length);
const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(envelope.nonce),additionalData:new TextEncoder().encode(run)},key,joined);
return JSON.parse(new TextDecoder().decode(plain));}
function fresh(d){return d.state!=='waiting'||(d.png&&d.expires>Date.now()/1000&&Date.now()/1000-(d.issued_at||d.expires-90)<20);}
let data;
try{const r=await fetch('https://raw.githubusercontent.com/'+owner+'/'+repo+'/auth/auth/'+run+'.json?t='+Date.now(),{cache:'no-store',signal:AbortSignal.timeout(8000)});if(r.ok)data=await decode(await r.json());}catch(e){if(e.name==='OperationError')throw e;}
if((!data||!fresh(data))&&Date.now()>=nextApiAt){
nextApiAt=Date.now()+65000;
try{
const r=await fetch('https://api.github.com/repos/'+owner+'/'+repo+'/contents/auth/'+run+'.json?ref=auth&t='+Date.now(),{cache:'no-store',headers:{Accept:'application/vnd.github+json'},signal:AbortSignal.timeout(8000)});
if(r.status===403||r.status===429){nextApiAt=Math.max(nextApiAt,Number(r.headers.get('x-ratelimit-reset'))*1000||0,Date.now()+(Number(r.headers.get('retry-after'))||60)*1000);apiNotice='GitHub API 暂时限流，已切换文件通道；请勿反复重启任务。';}
else if(r.ok){const f=await r.json();data=await decode(JSON.parse(new TextDecoder().decode(bytes(f.content.replace(/\s/g,'')))));apiNotice='';}
}catch(e){if(e.name==='OperationError')throw e;}
}
if(!data){img.hidden=true;img.removeAttribute('src');status.textContent=apiNotice||'尚未收到本次任务的二维码。页面会自动重试，请确认 GitHub 任务仍在运行。';return;}
img.hidden=true;img.removeAttribute('src');
if(data.state==='verified'){status.textContent='验证成功！GitHub 正在继续抓课。';clearInterval(timer);credentials=null;return;}
if(data.state!=='waiting'){status.textContent='验证会话已结束，请重新运行 GitHub 任务。';clearInterval(timer);credentials=null;return;}
if(!data.png){status.textContent=data.note||'学校尚未提供有效二维码，请查看本次任务日志。';return;}
const left=data.expires-Math.floor(Date.now()/1000);
if(left<=0||!fresh(data)){status.textContent=apiNotice||'当前二维码过旧，已隐藏；等待云端新二维码，请勿扫描旧截图。';return;}
img.src='data:image/png;base64,'+data.png;img.hidden=false;status.textContent='请扫码并确认，本二维码剩余约 '+left+' 秒。页面会自动更新。';
}catch(e){img.hidden=true;img.removeAttribute('src');status.textContent=e.name==='OperationError'?'无法解密，请检查学号和密码。':e.message;}finally{busy=false;}}
document.getElementById('form').onsubmit=e=>{e.preventDefault();if(!/^\d+-\d+$/.test(run||'')){status.textContent='缺少有效的任务编号';return;}credentials={student:document.getElementById('student').value.trim(),password:document.getElementById('password').value};document.getElementById('password').value='';clearInterval(timer);update();timer=setInterval(update,5000);};
</script></html>



