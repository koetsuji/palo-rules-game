import React, { useState, useEffect, useRef } from 'react';
import { Shield, Server, Globe, Play, RefreshCw, AlertTriangle, CheckCircle, Terminal, Database, Laptop, Wifi, ArrowRight, Lock, FileText, Activity, Save, Mail } from 'lucide-react';

// --- Game Constants & "Objects" ---
const ZONES = {
  trust: { id: 'trust', label: 'Trust-L3', color: 'emerald', ip: '10.1.1.0/24', int: 'eth1/2' },
  untrust: { id: 'untrust', label: 'Untrust-L3', color: 'blue', ip: '0.0.0.0/0', int: 'eth1/1' },
  dmz: { id: 'dmz', label: 'DMZ-L3', color: 'purple', ip: '192.168.50.0/24', int: 'eth1/3' },
  guest: { id: 'guest', label: 'Guest-L3', color: 'yellow', ip: '172.16.0.0/24', int: 'eth1/4' }
};

const APPS = [
  { id: 'any', label: 'any' },
  { id: 'web-browsing', label: 'web-browsing (HTTP)' },
  { id: 'ssl', label: 'ssl (HTTPS)' },
  { id: 'ssh', label: 'ssh' },
  { id: 'dns', label: 'dns' },
  { id: 'unknown-tcp', label: 'unknown-tcp' }
];

const SERVICES = [
  { id: 'application-default', label: 'application-default' },
  { id: 'service-http', label: 'service-http (80)' },
  { id: 'service-https', label: 'service-https (443)' },
  { id: 'any', label: 'any' }
];

const LEVELS = [
  {
    id: 1,
    title: "Secure Internet Access",
    desc: "Users in Trust need to browse secure websites (HTTPS). We must allow SSL and hide our internal subnet.",
    packet: { srcZone: 'trust', dstZone: 'untrust', srcIp: '10.1.1.55', dstIp: '142.250.1.1', proto: 'TCP/443', app: 'ssl' },
    solution: { srcZone: 'trust', dstZone: 'untrust', app: 'ssl', service: 'application-default', action: 'ALLOW', nat: 'SNAT' },
    hint: "Zone: Trust->Untrust. App: ssl. NAT: SNAT (Dynamic IP/Port)."
  },
  {
    id: 2,
    title: "Publishing DMZ Web Server",
    desc: "Public internet users need to access our Company Portal hosted in the DMZ on standard HTTP.",
    packet: { srcZone: 'untrust', dstZone: 'dmz', srcIp: '203.0.113.50', dstIp: '203.0.113.1', proto: 'TCP/80', app: 'web-browsing' },
    solution: { srcZone: 'untrust', dstZone: 'dmz', app: 'web-browsing', service: 'application-default', action: 'ALLOW', nat: 'DNAT' },
    hint: "Inbound traffic. Dest NAT required to map Public IP to DMZ Private IP."
  },
  {
    id: 3,
    title: "Block Non-Standard SSH",
    desc: "An internal developer is trying to SSH to a server in the DMZ, but they are using a non-standard high port (2222). Strict policy requires standard ports.",
    packet: { srcZone: 'trust', dstZone: 'dmz', srcIp: '10.1.1.100', dstIp: '192.168.50.5', proto: 'TCP/2222', app: 'ssh' },
    solution: { srcZone: 'trust', dstZone: 'dmz', app: 'ssh', service: 'application-default', action: 'ALLOW', nat: 'NONE' },
    specialCheck: (userConfig) => {
      if (userConfig.service === 'application-default') return { success: false, msg: "DROPPED: App-ID 'ssh' on port 2222 contradicts 'application-default' (Port 22). Good job enforcing standards!" }; 
      if (userConfig.service === 'any') return { success: true, msg: "WARNING: You allowed SSH on a non-standard port. It works, but violates security best practice." };
      return { success: false, msg: "Configuration mismatch." };
    },
    hint: "Use 'application-default' in the Service column to enforce standard ports. The packet SHOULD be dropped."
  },
  {
    id: 4,
    title: "The Hairpin (U-Turn) NAT",
    desc: "An internal user (Trust) is trying to access the DMZ Web Server via its PUBLIC IP. The traffic goes to the firewall and needs to turn back.",
    packet: { srcZone: 'trust', dstZone: 'untrust', srcIp: '10.1.1.50', dstIp: '203.0.113.1', proto: 'TCP/80', app: 'web-browsing' },
    solution: { srcZone: 'trust', dstZone: 'untrust', app: 'web-browsing', service: 'application-default', action: 'ALLOW', nat: 'DNAT+SNAT' },
    hint: "Complex! You need DNAT (to find the server) AND SNAT (so the server replies to the Firewall, not directly to the User)."
  },
  {
    id: 5,
    title: "Data Exfiltration Attempt",
    desc: "A compromised host in Guest is trying to tunnel data via DNS to a known C2 server.",
    packet: { srcZone: 'guest', dstZone: 'untrust', srcIp: '172.16.0.99', dstIp: '1.2.3.4', proto: 'UDP/53', app: 'dns' },
    solution: { srcZone: 'guest', dstZone: 'untrust', app: 'dns', service: 'application-default', action: 'DENY', nat: 'NONE' },
    hint: "This looks like normal DNS, but the destination is suspicious. Create a DENY rule."
  }
];

export default function FirewallNGFW() {
  const [levelIdx, setLevelIdx] = useState(0);
  const [gameState, setGameState] = useState('idle'); // idle, committing, animating, result
  const [logs, setLogs] = useState([]);
  const [commitProgress, setCommitProgress] = useState(0);
  
  // Animation State
  const [packetCoords, setPacketCoords] = useState({ x: 50, y: 50, opacity: 0 });
  
  // Policy State
  const [ruleName, setRuleName] = useState('Rule-1');
  const [srcZone, setSrcZone] = useState('trust');
  const [dstZone, setDstZone] = useState('untrust');
  const [app, setApp] = useState('any');
  const [service, setService] = useState('application-default');
  const [action, setAction] = useState('ALLOW');
  const [natType, setNatType] = useState('NONE');

  const level = LEVELS[levelIdx];

  // --- Animation Logic ---
  // Returns X/Y percentages for each zone
  const getZoneCoords = (zoneId) => {
    switch(zoneId) {
        case 'trust': return { x: 15, y: 20 };
        case 'untrust': return { x: 85, y: 20 };
        case 'guest': return { x: 15, y: 80 };
        case 'dmz': return { x: 85, y: 80 };
        case 'firewall': return { x: 50, y: 50 };
        default: return { x: 50, y: 50 };
    }
  };

  const startCommit = () => {
    setGameState('committing');
    setCommitProgress(0);
    
    // Reset Packet to Source
    const start = getZoneCoords(level.packet.srcZone);
    setPacketCoords({ ...start, opacity: 0 });

    let p = 0;
    const interval = setInterval(() => {
      p += 5;
      if (p >= 100) {
        clearInterval(interval);
        setCommitProgress(100);
        setTimeout(() => {
            setGameState('animating');
            runPacketAnimation();
        }, 500);
      } else {
        setCommitProgress(p);
      }
    }, 50);
  };

  const runPacketAnimation = () => {
    const start = getZoneCoords(level.packet.srcZone);
    const fw = getZoneCoords('firewall');
    const end = getZoneCoords(level.packet.dstZone);
    
    // Step 1: Appear at Source
    setPacketCoords({ ...start, opacity: 1 });

    // Step 2: Move to Firewall (1s)
    setTimeout(() => {
        setPacketCoords({ ...fw, opacity: 1 });
    }, 100);

    // Step 3: Process at Firewall (Wait 1s) & Decision
    setTimeout(() => {
        // Logic Check happens here mentally for the user
        evaluateTraffic(end);
    }, 1200);
  };

  const evaluateTraffic = (endCoords) => {
    // Artificial delay
    const config = { srcZone, dstZone, app, service, action, nat: natType };
    let finalAction = 'drop'; // drop or allow
    let resultMsg = "";
    let isWin = false;

    // ... Logic Check ...
    let logicPassed = true;
    
    // Special Check
    if (level.specialCheck) {
        const res = level.specialCheck(config);
        if (res.msg.includes("DROPPED") || res.msg.includes("WARNING")) {
            handleResult(true, res.msg, 'drop');
            setPacketCoords(prev => ({ ...prev, opacity: 0 })); // Disappear at FW
            return;
        }
    }

    if (srcZone !== level.packet.srcZone || dstZone !== level.packet.dstZone) { logicPassed = false; resultMsg = "Zone Mismatch"; }
    else if (app !== 'any' && app !== level.packet.app) { logicPassed = false; resultMsg = "App-ID Mismatch"; }
    else if (action !== level.solution.action) { logicPassed = false; resultMsg = "Action Mismatch"; }
    else if (action === 'ALLOW' && natType !== level.solution.nat) { logicPassed = false; resultMsg = "NAT Mismatch"; }

    if (logicPassed) {
        // Success Logic
        isWin = true;
        resultMsg = "Traffic Allowed";
        finalAction = action === 'DENY' ? 'drop' : 'allow';
    } else {
        // Failure Logic
        isWin = false;
        if (!resultMsg) resultMsg = "Incorrect Configuration";
        finalAction = 'drop'; // Even if they set ALLOW, if logic fail, we fail
    }

    // Step 4: Finish Animation
    if (finalAction === 'allow' && isWin) {
        // Move to Destination
        setPacketCoords({ ...endCoords, opacity: 1 });
        setTimeout(() => handleResult(true, resultMsg, 'allow'), 1000);
    } else {
        // Drop at Firewall (Turn Red/Fade)
        setPacketCoords(prev => ({ ...prev, opacity: 0, scale: 2 })); 
        setTimeout(() => handleResult(isWin, resultMsg, 'drop'), 500);
    }
  };

  const handleResult = (isWin, reason, effect) => {
    setGameState(isWin ? 'success' : 'failure');
    addLog(effect, reason);
  };

  const addLog = (action, reason) => {
    const newLog = {
      id: Date.now(),
      time: new Date().toLocaleTimeString(),
      src: level.packet.srcIp,
      dst: level.packet.dstIp,
      app: level.packet.app,
      action: action.toUpperCase(),
      bytes: action === 'allow' ? Math.floor(Math.random() * 5000) + 500 : 0,
      reason: reason
    };
    setLogs(prev => [newLog, ...prev]);
  };

  const nextLevel = () => {
    if (levelIdx < LEVELS.length - 1) {
      setLevelIdx(prev => prev + 1);
      setGameState('idle');
      setAction('ALLOW');
      setNatType('NONE');
      setApp('any');
      setPacketCoords({ x: 50, y: 50, opacity: 0 });
    } else {
      alert("PCNSE Certification Achieved! All scenarios complete.");
      setLevelIdx(0);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 font-sans flex flex-col">
      
      {/* Top Bar */}
      <div className="bg-slate-950 border-b border-slate-800 px-6 py-3 flex justify-between items-center z-50">
        <div className="flex items-center gap-3">
           <div className="bg-orange-600 p-1.5 rounded text-white"><Shield size={20} /></div>
           <div>
             <h1 className="font-bold text-lg text-slate-100 tracking-tight">PAN-OS <span className="text-orange-500">NGFW</span> SIMULATOR</h1>
             <div className="text-[10px] text-slate-500 font-mono">MANAGEMENT CONSOLE</div>
           </div>
        </div>
        <div className="flex items-center gap-6 text-xs font-mono">
           <div className="flex flex-col items-end">
             <span className="text-slate-500">DEVICE</span>
             <span className="text-emerald-400">PA-3220-HQ</span>
           </div>
           <div className="flex flex-col items-end">
             <span className="text-slate-500">UPTIME</span>
             <span className="text-slate-300">124d 03h 11m</span>
           </div>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-12 overflow-hidden relative">
         
         {/* Left Sidebar */}
         <div className="col-span-2 bg-slate-900 border-r border-slate-800 flex flex-col py-4 z-40">
            <div className="px-4 mb-6">
              <div className="text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Dashboard</div>
              <div className="space-y-1">
                 <div className="flex items-center gap-2 text-slate-300 bg-slate-800 px-3 py-2 rounded cursor-pointer border-l-2 border-orange-500"><Activity size={14}/> Monitor</div>
                 <div className="flex items-center gap-2 text-slate-400 px-3 py-2 hover:text-slate-200 cursor-pointer"><Lock size={14}/> Policies</div>
                 <div className="flex items-center gap-2 text-slate-400 px-3 py-2 hover:text-slate-200 cursor-pointer"><Globe size={14}/> Network</div>
                 <div className="flex items-center gap-2 text-slate-400 px-3 py-2 hover:text-slate-200 cursor-pointer"><Database size={14}/> Objects</div>
              </div>
            </div>

            <div className="px-4 mt-auto">
               <div className="bg-slate-800 rounded p-3 border border-slate-700">
                  <h3 className="text-xs font-bold text-orange-500 mb-1">Active Incident #{2040 + levelIdx}</h3>
                  <p className="text-[10px] text-slate-400 leading-tight mb-2">{level.desc}</p>
                  <div className="pt-2 border-t border-slate-700 grid grid-cols-1 gap-1 text-[9px] font-mono">
                     <div className="flex justify-between"><span className="text-slate-500">SRC:</span> <span className="text-white">{level.packet.srcIp}</span></div>
                     <div className="flex justify-between"><span className="text-slate-500">DST:</span> <span className="text-white">{level.packet.dstIp}</span></div>
                     <div className="flex justify-between"><span className="text-slate-500">APP:</span> <span className="text-white">{level.packet.app}</span></div>
                  </div>
               </div>
            </div>
         </div>

         {/* Center: Visualizer & Editor */}
         <div className="col-span-10 bg-slate-950 flex flex-col relative">
            
            {/* --- VISUALIZER PANEL (The Animation Zone) --- */}
            <div className="h-1/2 border-b border-slate-800 relative bg-[#0B1120] overflow-hidden">
                
                {/* Background Grid */}
                <div className="absolute inset-0 opacity-10" style={{backgroundImage: 'radial-gradient(#475569 1px, transparent 1px)', backgroundSize: '20px 20px'}}></div>

                {/* Commit Overlay */}
                {gameState === 'committing' && (
                   <div className="absolute inset-0 bg-slate-950/80 z-50 flex flex-col items-center justify-center backdrop-blur-sm">
                      <div className="w-64 bg-slate-800 rounded-full h-2 mb-4 overflow-hidden">
                         <div className="bg-orange-500 h-full transition-all duration-200 ease-out" style={{width: `${commitProgress}%`}}></div>
                      </div>
                      <div className="text-orange-500 font-mono text-sm animate-pulse">Committing Configuration... {commitProgress}%</div>
                   </div>
                )}

                {/* --- PACKET ANIMATION --- */}
                {/* This is the moving dot */}
                <div 
                    className="absolute z-30 transition-all duration-1000 ease-in-out flex flex-col items-center justify-center pointer-events-none"
                    style={{
                        left: `${packetCoords.x}%`,
                        top: `${packetCoords.y}%`,
                        opacity: packetCoords.opacity,
                        transform: 'translate(-50%, -50%)'
                    }}
                >
                    <div className="w-8 h-8 bg-white rounded-full shadow-[0_0_20px_rgba(255,255,255,0.8)] flex items-center justify-center relative">
                        <div className="absolute inset-0 bg-white rounded-full animate-ping opacity-75"></div>
                        {level.packet.app === 'ssl' ? <Lock size={14} className="text-black" /> : 
                         level.packet.app === 'dns' ? <Globe size={14} className="text-black" /> :
                         <FileText size={14} className="text-black" />}
                    </div>
                    <div className="mt-2 bg-black/80 text-white text-[9px] px-2 py-1 rounded border border-slate-600 whitespace-nowrap">
                        {level.packet.proto}
                    </div>
                </div>


                {/* --- TOPOLOGY MAP --- */}
                <div className="absolute inset-0 p-6">
                    {/* Top Row */}
                    <div className="flex justify-between h-full">
                        <div className="flex flex-col justify-between w-full">
                            
                            {/* Row 1: Trust & Untrust */}
                            <div className="flex justify-between">
                                {/* Trust Zone */}
                                <div className={`w-48 h-32 border-2 border-dashed rounded-xl p-3 relative transition-all duration-500 ${level.packet.srcZone === 'trust' ? 'border-emerald-500 bg-emerald-900/10 shadow-[0_0_30px_rgba(16,185,129,0.1)]' : 'border-slate-800 bg-slate-900/50'}`}>
                                    <div className="text-emerald-500 font-bold text-xs flex items-center gap-2"><Laptop size={14}/> TRUST-L3</div>
                                    <div className="absolute bottom-2 right-2 opacity-20"><Laptop size={40}/></div>
                                </div>
                                
                                {/* Untrust Zone */}
                                <div className={`w-48 h-32 border-2 border-dashed rounded-xl p-3 relative transition-all duration-500 ${level.packet.dstZone === 'untrust' ? 'border-blue-500 bg-blue-900/10 shadow-[0_0_30px_rgba(59,130,246,0.1)]' : 'border-slate-800 bg-slate-900/50'}`}>
                                    <div className="text-blue-500 font-bold text-xs flex items-center gap-2 justify-end">UNTRUST-L3 <Globe size={14}/></div>
                                    <div className="absolute bottom-2 left-2 opacity-20"><Globe size={40}/></div>
                                </div>
                            </div>

                            {/* Center Firewall */}
                            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10">
                                <div className="w-40 h-40 bg-slate-800 rounded-lg border-2 border-orange-500 shadow-[0_0_50px_rgba(249,115,22,0.2)] flex flex-col items-center justify-center relative">
                                    <div className="text-orange-500 mb-2"><Shield size={48} /></div>
                                    <div className="text-[10px] font-bold text-white">PA-3220</div>
                                    <div className="text-[9px] text-slate-400 font-mono mt-1">203.0.113.1</div>
                                    {/* Interfaces */}
                                    <div className="absolute -left-2 top-8 bg-slate-900 text-[8px] px-1 border border-slate-600 rounded text-emerald-500">e1/2</div>
                                    <div className="absolute -right-2 top-8 bg-slate-900 text-[8px] px-1 border border-slate-600 rounded text-blue-500">e1/1</div>
                                    <div className="absolute -left-2 bottom-8 bg-slate-900 text-[8px] px-1 border border-slate-600 rounded text-yellow-500">e1/4</div>
                                    <div className="absolute -right-2 bottom-8 bg-slate-900 text-[8px] px-1 border border-slate-600 rounded text-purple-500">e1/3</div>
                                </div>
                            </div>

                            {/* Row 2: Guest & DMZ */}
                            <div className="flex justify-between">
                                {/* Guest Zone */}
                                <div className={`w-48 h-32 border-2 border-dashed rounded-xl p-3 relative transition-all duration-500 ${level.packet.srcZone === 'guest' ? 'border-yellow-500 bg-yellow-900/10 shadow-[0_0_30px_rgba(234,179,8,0.1)]' : 'border-slate-800 bg-slate-900/50'}`}>
                                    <div className="text-yellow-500 font-bold text-xs flex items-center gap-2"><Wifi size={14}/> GUEST-L3</div>
                                    <div className="absolute bottom-2 right-2 opacity-20"><Wifi size={40}/></div>
                                </div>

                                {/* DMZ Zone */}
                                <div className={`w-48 h-32 border-2 border-dashed rounded-xl p-3 relative transition-all duration-500 ${level.packet.dstZone === 'dmz' ? 'border-purple-500 bg-purple-900/10 shadow-[0_0_30px_rgba(168,85,247,0.1)]' : 'border-slate-800 bg-slate-900/50'}`}>
                                    <div className="text-purple-500 font-bold text-xs flex items-center gap-2 justify-end">DMZ-L3 <Server size={14}/></div>
                                    <div className="absolute bottom-2 left-2 opacity-20"><Server size={40}/></div>
                                </div>
                            </div>

                        </div>
                    </div>
                </div>

                {/* Results Modal */}
                {(gameState === 'success' || gameState === 'failure') && (
                  <div className="absolute inset-0 z-50 bg-slate-950/90 flex items-center justify-center animate-in fade-in zoom-in duration-300">
                     <div className={`p-8 rounded-xl border shadow-2xl max-w-md text-center backdrop-blur-md ${gameState === 'success' ? 'border-emerald-500 bg-emerald-950/50' : 'border-red-500 bg-red-950/50'}`}>
                        {gameState === 'success' ? <CheckCircle className="w-16 h-16 text-emerald-500 mx-auto mb-4"/> : <AlertTriangle className="w-16 h-16 text-red-500 mx-auto mb-4"/>}
                        <h3 className="text-2xl font-bold text-white mb-2">{gameState === 'success' ? "TRAFFIC ALLOWED" : "POLICY BLOCKED"}</h3>
                        <p className="text-sm text-slate-300 mb-8 leading-relaxed">{logs[0]?.reason}</p>
                        {gameState === 'success' ? (
                           <button onClick={nextLevel} className="bg-emerald-600 hover:bg-emerald-500 text-white px-8 py-3 rounded-lg font-bold flex items-center gap-2 mx-auto transition-all hover:scale-105">Next Scenario <ArrowRight size={18}/></button>
                        ) : (
                           <button onClick={() => setGameState('idle')} className="bg-slate-700 hover:bg-slate-600 text-white px-8 py-3 rounded-lg font-bold flex items-center gap-2 mx-auto transition-all hover:scale-105"><RefreshCw size={18}/> Reconfigure</button>
                        )}
                     </div>
                  </div>
                )}
            </div>

            {/* --- EDITOR & LOGS (Bottom Half) --- */}
            <div className="h-1/2 flex flex-col bg-slate-900">
               {/* Tabs */}
               <div className="bg-slate-900 border-b border-slate-800 flex px-4 shadow-md z-10">
                  <div className="px-4 py-3 text-xs font-bold text-orange-500 border-b-2 border-orange-500 bg-slate-800/50">Security Policy Rulebase</div>
                  <div className="px-4 py-3 text-xs font-bold text-slate-500 hover:text-slate-300 cursor-pointer">NAT Policy</div>
                  <div className="px-4 py-3 text-xs font-bold text-slate-500 hover:text-slate-300 cursor-pointer">Monitor</div>
               </div>

               {/* Rule Editor Table */}
               <div className="p-4 overflow-auto flex-1 bg-slate-900/50 relative">
                  <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-slate-700 to-transparent opacity-20"></div>
                  <table className="w-full text-left border-collapse">
                     <thead>
                        <tr className="text-[10px] text-slate-500 font-bold uppercase border-b border-slate-700">
                           <th className="p-2 w-32">Name</th>
                           <th className="p-2">Source Zone</th>
                           <th className="p-2">Dest Zone</th>
                           <th className="p-2">Application</th>
                           <th className="p-2">Service</th>
                           <th className="p-2">Action</th>
                           <th className="p-2">NAT Profile</th>
                        </tr>
                     </thead>
                     <tbody>
                        <tr className="bg-slate-800 text-xs border-l-4 border-orange-500 shadow-sm">
                           <td className="p-2 border-r border-slate-700">
                              <input value={ruleName} onChange={(e)=>setRuleName(e.target.value)} className="bg-transparent text-white font-bold w-full outline-none" />
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={srcZone} onChange={(e)=>setSrcZone(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-2 py-1 outline-none focus:border-orange-500 text-[10px] w-full text-emerald-400" disabled={gameState !== 'idle'}>
                                 {Object.values(ZONES).map(z => <option key={z.id} value={z.id}>{z.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={dstZone} onChange={(e)=>setDstZone(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-2 py-1 outline-none focus:border-orange-500 text-[10px] w-full text-blue-400" disabled={gameState !== 'idle'}>
                                 {Object.values(ZONES).map(z => <option key={z.id} value={z.id}>{z.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={app} onChange={(e)=>setApp(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-2 py-1 outline-none focus:border-orange-500 text-[10px] w-full" disabled={gameState !== 'idle'}>
                                 {APPS.map(a => <option key={a.id} value={a.id}>{a.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={service} onChange={(e)=>setService(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-2 py-1 outline-none focus:border-orange-500 text-[10px] w-full" disabled={gameState !== 'idle'}>
                                 {SERVICES.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={action} onChange={(e)=>setAction(e.target.value)} className={`border rounded px-2 py-1 outline-none font-bold text-[10px] w-20 cursor-pointer ${action === 'ALLOW' ? 'bg-emerald-900 border-emerald-700 text-emerald-400' : 'bg-red-900 border-red-700 text-red-400'}`} disabled={gameState !== 'idle'}>
                                 <option value="ALLOW">Allow</option>
                                 <option value="DENY">Deny</option>
                              </select>
                           </td>
                           <td className="p-2">
                              <select value={natType} onChange={(e)=>setNatType(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-2 py-1 outline-none focus:border-orange-500 text-[10px] w-full" disabled={gameState !== 'idle'}>
                                 <option value="NONE">None</option>
                                 <option value="SNAT">Source NAT</option>
                                 <option value="DNAT">Dest NAT</option>
                                 <option value="DNAT+SNAT">U-Turn (Both)</option>
                              </select>
                           </td>
                        </tr>
                     </tbody>
                  </table>
               </div>

               {/* Logs Footer */}
               <div className="h-32 bg-slate-950 border-t border-slate-800 flex flex-col">
                  <div className="px-3 py-1 bg-slate-900 text-[10px] text-slate-400 font-bold flex justify-between border-b border-slate-800">
                     <span>TRAFFIC LOGS (REALTIME)</span>
                     <span className="text-emerald-500 cursor-pointer hover:underline flex items-center gap-1"><Save size={10}/> Export CSV</span>
                  </div>
                  <div className="overflow-auto flex-1">
                     <table className="w-full text-left text-[10px] font-mono">
                        <thead className="sticky top-0 bg-slate-950 text-slate-500">
                            <tr>
                                <th className="p-1 font-normal">Time</th>
                                <th className="p-1 font-normal">Source</th>
                                <th className="p-1 font-normal">Destination</th>
                                <th className="p-1 font-normal">App</th>
                                <th className="p-1 font-normal">Action</th>
                                <th className="p-1 font-normal">Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                           {logs.map(log => (
                              <tr key={log.id} className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                                 <td className="p-1 text-slate-500">{log.time}</td>
                                 <td className="p-1 text-emerald-400">{log.src}</td>
                                 <td className="p-1 text-blue-400">{log.dst}</td>
                                 <td className="p-1 text-purple-400 flex items-center gap-1">
                                    {log.app === 'ssl' && <Lock size={8}/>}
                                    {log.app}
                                 </td>
                                 <td className={`p-1 font-bold ${log.action === 'ALLOW' ? 'text-green-500' : 'text-red-500'}`}>{log.action}</td>
                                 <td className="p-1 text-slate-400 italic max-w-xs truncate">{log.reason}</td>
                              </tr>
                           ))}
                        </tbody>
                     </table>
                  </div>
               </div>
            </div>

            {/* Commit Button (Floating) */}
            <div className="absolute bottom-36 right-6 z-50">
               <button 
                  onClick={startCommit}
                  disabled={gameState !== 'idle'}
                  className={`flex items-center gap-2 px-6 py-4 rounded-lg shadow-2xl font-bold text-sm transition-all transform
                     ${gameState === 'idle' ? 'bg-orange-600 hover:bg-orange-500 text-white hover:scale-105 hover:-translate-y-1' : 'bg-slate-700 text-slate-500 cursor-not-allowed'}`}
               >
                  <Save size={18} /> {gameState === 'committing' ? 'Committing...' : 'Commit Changes'}
               </button>
            </div>

         </div>
      </div>
    </div>
  );
}