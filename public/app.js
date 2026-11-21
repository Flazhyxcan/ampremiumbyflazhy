const $=id=>document.getElementById(id);
let mode="login",tick;
const api=async(p,b)=>{const r=await fetch("/api/"+p,{method:b?"POST":"GET",headers:{"Content-Type":"application/json","X-Requested-With":"am"},body:b?JSON.stringify(b):undefined});const j=await r.json().catch(()=>({}));if(!r.ok){const e=new Error(j.error||"Terjadi kesalahan.");e.data=j;throw e}return j};
const say=(id,t,c)=>{$(id).textContent=t;$(id).className="msg "+(c||"")};
function show(u){
  $("auth").classList.add("hide");$("app").classList.remove("hide");
  $("cr").textContent=u.credits;
  clearInterval(tick);let left=u.resetIn;
  const draw=()=>{const h=Math.floor(left/36e5),m=Math.floor(left%36e5/6e4);$("rs").textContent=u.credits<1?`Kredit habis. Reset dalam ${h} jam ${m} menit.`:"Dua langkah: kirim email verifikasi, lalu tempel link-nya.";left-=3e4};
  draw();tick=setInterval(draw,3e4);
}
const sw=m=>{mode=m;$("tL").classList.toggle("on",m==="login");$("tR").classList.toggle("on",m==="register");$("go").textContent=m==="login"?"Login":"Buat akun";say("m1","")};
$("tL").onclick=()=>sw("login");$("tR").onclick=()=>sw("register");
async function run(btn,fn){btn.disabled=true;try{await fn()}finally{btn.disabled=false}}
$("go").onclick=e=>run(e.target,async()=>{try{show(await api(mode==="login"?"login":"register",{username:$("u").value,password:$("p").value}))}catch(x){say("m1",x.message,"err")}});
$("s1").onclick=e=>run(e.target,async()=>{say("m2","Mengirim…");try{const j=await api("send",{email:$("em").value});show(j);say("m2",j.message,"ok")}catch(x){if(x.data&&x.data.credits!==undefined)show(x.data);say("m2",x.message,"err")}});
$("s2").onclick=e=>run(e.target,async()=>{say("m2","Memverifikasi…");try{const j=await api("verify",{email:$("em").value,link:$("lk").value});say("m2",j.message,"ok")}catch(x){say("m2",x.message,"err")}});
$("lo").onclick=async()=>{await api("logout",{});location.reload()};
api("me").then(show).catch(()=>{});