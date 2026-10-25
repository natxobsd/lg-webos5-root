// NATXO boot-escalate hook for CYTV nativehome service.
// Appended to service.js on models without chokidar (e.g. NANO95/E60).
// 5s after service startup, checks if root SSH (port 22) is already up;
// if not, spawns the GFX credential escalation to get root and start sshd.
// Safe no-op if the GFX device is absent or escalation is not installed.
// NATXO_NATIVEHOME_HOOK
setTimeout(function(){try{var n=require("net"),s=new n.Socket();s.setTimeout(2e3);s.connect(22,"127.0.0.1",function(){s.destroy()});s.on("error",function(){s.destroy();try{require("child_process").exec("python /media/developer/natxo/boot-escalate.py >/dev/null 2>&1 &")}catch(e){}});s.on("timeout",function(){s.destroy();try{require("child_process").exec("python /media/developer/natxo/boot-escalate.py >/dev/null 2>&1 &")}catch(e){}})}catch(e){}},5e3);
// /NATXO_NATIVEHOME_HOOK
