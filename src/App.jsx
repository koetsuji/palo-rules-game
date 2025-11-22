import React, { useState, useEffect, useRef } from 'react';
import { Shield, Server, Globe, Play, RefreshCw, AlertTriangle, CheckCircle, Terminal, Database, Laptop, Wifi, ArrowRight, Lock, FileText, Activity, Save } from 'lucide-react';

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
    solution: { 
      srcZone: 'trust', dstZone: 'untrust', 
      app: 'ssl', service: 'application-default',
      action: 'ALLOW', nat: 'SNAT' 
    },
    hint: "Zone: Trust->Untrust. App: ssl. NAT: SNAT (Dynamic IP/Port)."
  },
  {
    id: 2,
    title: "Publishing DMZ Web Server",
    desc: "Public internet users need to access our Company Portal hosted in the DMZ on standard HTTP.",
    packet: { srcZone: 'untrust', dstZone: 'dmz', srcIp: '203.0.113.50', dstIp: '203.0.113.1', proto: 'TCP/80', app: 'web-browsing' },
    solution: { 
      srcZone: 'untrust', dstZone: 'dmz', // Note: In PAN-OS, Sec policy uses Pre-NAT IP but Post-NAT Zone (DMZ). For simplicity here, we use visual flow Untrust->DMZ
      app: 'web-browsing', service: 'application-default',
      action: 'ALLOW', nat: 'DNAT' 
    },
    hint: "Inbound traffic. Dest NAT required to map Public IP to DMZ Private IP."
  },
  {
    id: 3,
    title: "Block Non-Standard SSH",
    desc: "An internal developer is trying to SSH to a server in the DMZ, but they are using a non-standard high port (2222). Strict policy requires standard ports.",
    packet: { srcZone: 'trust', dstZone: 'dmz', srcIp: '10.1.1.100', dstIp: '192.168.50.5', proto: 'TCP/2222', app: 'ssh' },
    solution: { 
      srcZone: 'trust', dstZone: 'dmz',
      app: 'ssh', service: 'application-default', // App-default enforces port 22. 
      action: 'ALLOW', nat: 'NONE' // Wait, if we enforce app-default, this packet should FAIL/DROP naturally if the rule expects port 22 but packet is 2222.
    },
    specialCheck: (userConfig) => {
      // If user selects 'application-default', this packet (on 2222) will be dropped by the firewall because ssh expects 22.
      // If user selects 'any' service, it might pass (bad practice).
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
    solution: { 
      srcZone: 'trust', dstZone: 'untrust', // Traffic targets Public IP (Untrust zone) initially
      app: 'web-browsing', service: 'application-default',
      action: 'ALLOW', nat: 'DNAT+SNAT' // Needs both to prevent asymmetric routing
    },
    hint: "Complex! You need DNAT (to find the server) AND SNAT (so the server replies to the Firewall, not directly to the User)."
  },
  {
    id: 5,
    title: "Data Exfiltration Attempt",
    desc: "A compromised host in Guest is trying to tunnel data via DNS to a known C2 server.",
    packet: { srcZone: 'guest', dstZone: 'untrust', srcIp: '172.16.0.99', dstIp: '1.2.3.4', proto: 'UDP/53', app: 'dns' },
    solution: { 
      srcZone: 'guest', dstZone: 'untrust',
      app: 'dns', service: 'application-default',
      action: 'DENY', nat: 'NONE'
    },
    hint: "This looks like normal DNS, but the destination is suspicious. Create a DENY rule."
  }
];

export default function FirewallNGFW() {
  const [levelIdx, setLevelIdx] = useState(0);
  const [gameState, setGameState] = useState('idle'); // idle, committing, animating, result
  const [logs, setLogs] = useState([]);
  const [commitProgress, setCommitProgress] = useState(0);
  
  // Policy State
  const [ruleName, setRuleName] = useState('Rule-1');
  const [srcZone, setSrcZone] = useState('trust');
  const [dstZone, setDstZone] = useState('untrust');
  const [app, setApp] = useState('any');
  const [service, setService] = useState('application-default');
  const [action, setAction] = useState('ALLOW');
  const [natType, setNatType] = useState('NONE');

  const level = LEVELS[levelIdx];

  // --- Logic Engine ---
  const startCommit = () => {
    setGameState('committing');
    setCommitProgress(0);
    
    // Simulate PAN-OS Commit time
    let p = 0;
    const interval = setInterval(() => {
      p += Math.floor(Math.random() * 15) + 5;
      if (p >= 100) {
        clearInterval(interval);
        setCommitProgress(100);
        setTimeout(() => {
            setGameState('animating');
            evaluateTraffic();
        }, 500);
      } else {
        setCommitProgress(p);
      }
    }, 200);
  };

  const evaluateTraffic = () => {
    // Artificial delay for animation
    setTimeout(() => {
      const config = { srcZone, dstZone, app, service, action, nat: natType };
      let success = false;
      let msg = "";

      // Special Case Logic (Level 3)
      if (level.specialCheck) {
        const res = level.specialCheck(config);
        // Special check returns success if the OUTCOME matches expectation (even if outcome is drop)
        // For Level 3, we WANT it to drop if app-default is used.
        if (res.msg.includes("DROPPED") || res.msg.includes("WARNING")) {
            // This is a "Pass" in terms of game progression, even if packet dropped
            handleResult(true, res.msg, 'drop'); 
            return;
        }
      }

      // Standard Logic
      // 1. Zone Check
      if (srcZone !== level.packet.srcZone || dstZone !== level.packet.dstZone) {
         // Exception for Hairpin: User targets Untrust IP, so Dest Zone is Untrust in policy (usually)
         // For simplicity in this game, we demand exact match unless specified.
         handleResult(false, "Zone Mismatch: Traffic did not match policy scope.", 'drop');
         return;
      }

      // 2. App Check
      if (app !== 'any' && app !== level.packet.app) {
         handleResult(false, "App-ID Mismatch: Rule App does not match traffic.", 'drop');
         return;
      }

      // 3. Security Action Check
      if (action !== level.solution.action) {
         if (level.solution.action === 'DENY') handleResult(false, "Security Risk: Traffic allowed but should be blocked.", 'allow');
         else handleResult(false, "Traffic Blocked: Legitimate traffic was denied.", 'drop');
         return;
      }

      // 4. NAT Check (only if allowed)
      if (action === 'ALLOW') {
         if (natType !== level.solution.nat) {
            handleResult(false, `NAT Config Error: Expected ${level.solution.nat}, got ${natType}.`, 'drop');
            return;
         }
      }

      // If we got here
      if (action === 'DENY') handleResult(true, "Threat Blocked successfully.", 'drop');
      else handleResult(true, "Traffic Allowed & Processed correctly.", 'allow');

    }, 2000);
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
      // Reset risky fields, keep safe ones
      setAction('ALLOW');
      setNatType('NONE');
      setApp('any');
    } else {
      alert("PCNSE Certification Achieved! All scenarios complete.");
      setLevelIdx(0);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 font-sans flex flex-col">
      
      {/* Top Bar: Dashboard Style */}
      <div className="bg-slate-950 border-b border-slate-800 px-6 py-3 flex justify-between items-center">
        <div className="flex items-center gap-3">
           <div className="bg-orange-600 p-1.5 rounded text-white"><Shield size={20} /></div>
           <div>
             <h1 className="font-bold text-lg text-slate-100 tracking-tight">PAN-OS <span className="text-orange-500">NGFW</span> SIMULATOR</h1>
             <div className="text-[10px] text-slate-500 font-mono">MANAGEMENT CONSOLE</div>
           </div>
        </div>
        <div className="flex items-center gap-6 text-xs font-mono">
           <div className="flex flex-col items-end">
             <span className="text-slate-500">DEVICE NAME</span>
             <span className="text-emerald-400">PA-3220-HQ</span>
           </div>
           <div className="flex flex-col items-end">
             <span className="text-slate-500">UPTIME</span>
             <span className="text-slate-300">124d 03h 11m</span>
           </div>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-12 overflow-hidden">
         
         {/* LEFT: Navigation/Context (Static) */}
         <div className="col-span-2 bg-slate-900 border-r border-slate-800 flex flex-col py-4">
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
                  <p className="text-[10px] text-slate-400 leading-tight">{level.desc}</p>
                  <div className="mt-2 pt-2 border-t border-slate-700 grid grid-cols-2 gap-2 text-[9px] font-mono">
                     <div>SRC: <span className="text-white">{level.packet.srcIp}</span></div>
                     <div>DST: <span className="text-white">{level.packet.dstIp}</span></div>
                     <div>APP: <span className="text-white">{level.packet.app}</span></div>
                     <div>PRT: <span className="text-white">{level.packet.proto}</span></div>
                  </div>
               </div>
            </div>
         </div>

         {/* CENTER: Policy Editor & Visualizer */}
         <div className="col-span-10 bg-slate-950 flex flex-col relative">
            
            {/* Visualizer Panel */}
            <div className="h-1/2 border-b border-slate-800 p-6 relative bg-slate-900/50">
                {/* Commit Overlay */}
                {gameState === 'committing' && (
                   <div className="absolute inset-0 bg-slate-950/80 z-50 flex flex-col items-center justify-center">
                      <div className="w-64 bg-slate-800 rounded-full h-2 mb-4 overflow-hidden">
                         <div className="bg-orange-500 h-full transition-all duration-200 ease-out" style={{width: `${commitProgress}%`}}></div>
                      </div>
                      <div className="text-orange-500 font-mono text-sm animate-pulse">Committing Configuration... {commitProgress}%</div>
                   </div>
                )}

                {/* Topology */}
                <div className="w-full h-full grid grid-cols-4 gap-4">
                    {/* ZONES */}
                    <div className="col-span-1 flex flex-col gap-4">
                       <div className={`flex-1 border border-dashed border-emerald-800 bg-emerald-900/5 rounded p-2 relative ${level.packet.srcZone === 'trust' ? 'ring-1 ring-emerald-500' : ''}`}>
                          <div className="text-emerald-600 font-bold text-xs flex items-center gap-2"><Laptop size={12}/> TRUST-L3</div>
                          {level.packet.srcZone === 'trust' && <div className="absolute right-2 top-10 animate-bounce"><span className="text-xs">👤</span></div>}
                       </div>
                       <div className={`flex-1 border border-dashed border-yellow-800 bg-yellow-900/5 rounded p-2 relative ${level.packet.srcZone === 'guest' ? 'ring-1 ring-yellow-500' : ''}`}>
                          <div className="text-yellow-600 font-bold text-xs flex items-center gap-2"><Wifi size={12}/> GUEST-L3</div>
                          {level.packet.srcZone === 'guest' && <div className="absolute right-2 top-10 animate-bounce"><span className="text-xs">👤</span></div>}
                       </div>
                    </div>

                    {/* FIREWALL */}
                    <div className="col-span-2 flex items-center justify-center relative">
                       {/* Packet Animation */}
                       {gameState === 'animating' && (
                          <div className="absolute left-0 w-full h-1 bg-slate-800 overflow-hidden">
                             <div className="w-20 h-full bg-gradient-to-r from-transparent via-orange-500 to-transparent animate-[shimmer_1s_infinite]"></div>
                          </div>
                       )}
                       
                       <div className="w-64 h-32 bg-slate-800 rounded border border-slate-600 shadow-2xl flex flex-col relative z-10">
                          <div className="bg-slate-700 p-2 flex justify-between items-center border-b border-slate-600">
                             <div className="flex gap-1">
                               <div className="w-2 h-2 rounded-full bg-green-500"></div>
                               <div className="w-2 h-2 rounded-full bg-slate-500"></div>
                             </div>
                             <div className="text-[9px] font-mono text-slate-400">PA-3220</div>
                          </div>
                          <div className="flex-1 flex items-center justify-center">
                             <Shield className={`w-12 h-12 text-slate-600 ${gameState === 'animating' ? 'text-orange-500 animate-pulse' : ''}`} />
                          </div>
                          {/* Ports */}
                          <div className="flex justify-around pb-1 px-2">
                             <div className="w-3 h-3 bg-slate-900 border border-slate-600 text-[6px] flex items-center justify-center text-emerald-500">1/2</div>
                             <div className="w-3 h-3 bg-slate-900 border border-slate-600 text-[6px] flex items-center justify-center text-yellow-500">1/4</div>
                             <div className="w-3 h-3 bg-slate-900 border border-slate-600 text-[6px] flex items-center justify-center text-purple-500">1/3</div>
                             <div className="w-3 h-3 bg-slate-900 border border-slate-600 text-[6px] flex items-center justify-center text-blue-500">1/1</div>
                          </div>
                       </div>
                    </div>

                    {/* DEST ZONES */}
                    <div className="col-span-1 flex flex-col gap-4">
                       <div className={`flex-1 border border-dashed border-blue-800 bg-blue-900/5 rounded p-2 relative ${level.packet.dstZone === 'untrust' ? 'ring-1 ring-blue-500' : ''}`}>
                          <div className="text-blue-600 font-bold text-xs flex items-center gap-2 justify-end">UNTRUST-L3 <Globe size={12}/></div>
                       </div>
                       <div className={`flex-1 border border-dashed border-purple-800 bg-purple-900/5 rounded p-2 relative ${level.packet.dstZone === 'dmz' ? 'ring-1 ring-purple-500' : ''}`}>
                          <div className="text-purple-600 font-bold text-xs flex items-center gap-2 justify-end">DMZ-L3 <Server size={12}/></div>
                          {level.packet.dstZone === 'dmz' && <div className="absolute left-2 top-10"><Server size={16} className="text-purple-400"/></div>}
                       </div>
                    </div>
                </div>

                {/* Results Modal */}
                {(gameState === 'success' || gameState === 'failure') && (
                  <div className="absolute inset-0 z-50 bg-slate-950/90 flex items-center justify-center">
                     <div className={`p-6 rounded-lg border shadow-2xl max-w-md text-center ${gameState === 'success' ? 'border-emerald-500 bg-emerald-950/30' : 'border-red-500 bg-red-950/30'}`}>
                        {gameState === 'success' ? <CheckCircle className="w-12 h-12 text-emerald-500 mx-auto mb-3"/> : <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-3"/>}
                        <h3 className="text-xl font-bold text-white mb-2">{gameState === 'success' ? "TRAFFIC PROCESSED" : "POLICY FAILURE"}</h3>
                        <p className="text-sm text-slate-300 mb-6">{logs[0]?.reason}</p>
                        {gameState === 'success' ? (
                           <button onClick={nextLevel} className="bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-2 rounded text-sm font-bold flex items-center gap-2 mx-auto">Next Scenario <ArrowRight size={14}/></button>
                        ) : (
                           <button onClick={() => setGameState('idle')} className="bg-slate-700 hover:bg-slate-600 text-white px-6 py-2 rounded text-sm font-bold flex items-center gap-2 mx-auto"><RefreshCw size={14}/> Reconfigure</button>
                        )}
                     </div>
                  </div>
                )}
            </div>

            {/* Editor & Monitor Panel */}
            <div className="h-1/2 flex flex-col">
               {/* Tabs */}
               <div className="bg-slate-900 border-b border-slate-800 flex px-4">
                  <div className="px-4 py-2 text-xs font-bold text-orange-500 border-b-2 border-orange-500">Security Policy Rulebase</div>
                  <div className="px-4 py-2 text-xs font-bold text-slate-500 hover:text-slate-300 cursor-pointer">NAT Policy</div>
                  <div className="px-4 py-2 text-xs font-bold text-slate-500 hover:text-slate-300 cursor-pointer">Monitor</div>
               </div>

               {/* Rule Editor Table */}
               <div className="p-4 overflow-auto flex-1 bg-slate-900/50">
                  <table className="w-full text-left border-collapse">
                     <thead>
                        <tr className="text-[10px] text-slate-500 font-bold uppercase border-b border-slate-700">
                           <th className="p-2">Name</th>
                           <th className="p-2">Source Zone</th>
                           <th className="p-2">Dest Zone</th>
                           <th className="p-2">Application</th>
                           <th className="p-2">Service</th>
                           <th className="p-2">Action</th>
                           <th className="p-2">NAT Profile</th>
                        </tr>
                     </thead>
                     <tbody>
                        <tr className="bg-slate-800 text-xs">
                           <td className="p-2 border-r border-slate-700">
                              <input value={ruleName} onChange={(e)=>setRuleName(e.target.value)} className="bg-transparent text-orange-400 w-20 outline-none" />
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={srcZone} onChange={(e)=>setSrcZone(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-1 py-0.5 outline-none focus:border-orange-500 text-[10px] w-24" disabled={gameState !== 'idle'}>
                                 {Object.values(ZONES).map(z => <option key={z.id} value={z.id}>{z.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={dstZone} onChange={(e)=>setDstZone(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-1 py-0.5 outline-none focus:border-orange-500 text-[10px] w-24" disabled={gameState !== 'idle'}>
                                 {Object.values(ZONES).map(z => <option key={z.id} value={z.id}>{z.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={app} onChange={(e)=>setApp(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-1 py-0.5 outline-none focus:border-orange-500 text-[10px] w-28" disabled={gameState !== 'idle'}>
                                 {APPS.map(a => <option key={a.id} value={a.id}>{a.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={service} onChange={(e)=>setService(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-1 py-0.5 outline-none focus:border-orange-500 text-[10px] w-28" disabled={gameState !== 'idle'}>
                                 {SERVICES.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
                              </select>
                           </td>
                           <td className="p-2 border-r border-slate-700">
                              <select value={action} onChange={(e)=>setAction(e.target.value)} className={`border rounded px-1 py-0.5 outline-none font-bold text-[10px] w-20 ${action === 'ALLOW' ? 'bg-emerald-900 border-emerald-700 text-emerald-400' : 'bg-red-900 border-red-700 text-red-400'}`} disabled={gameState !== 'idle'}>
                                 <option value="ALLOW">Allow</option>
                                 <option value="DENY">Deny</option>
                              </select>
                           </td>
                           <td className="p-2">
                              <select value={natType} onChange={(e)=>setNatType(e.target.value)} className="bg-slate-900 border border-slate-600 rounded px-1 py-0.5 outline-none focus:border-orange-500 text-[10px] w-28" disabled={gameState !== 'idle'}>
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
               <div className="h-24 bg-slate-950 border-t border-slate-800 flex flex-col">
                  <div className="px-2 py-1 bg-slate-900 text-[10px] text-slate-400 font-bold flex justify-between">
                     <span>TRAFFIC LOGS (LAST 5)</span>
                     <span className="text-emerald-500 cursor-pointer hover:underline">Export CSV</span>
                  </div>
                  <div className="overflow-auto flex-1">
                     <table className="w-full text-left text-[10px] font-mono">
                        <tbody>
                           {logs.map(log => (
                              <tr key={log.id} className="border-b border-slate-800 hover:bg-slate-800">
                                 <td className="p-1 text-slate-500">{log.time}</td>
                                 <td className="p-1 text-emerald-400">{log.src}</td>
                                 <td className="p-1 text-blue-400">{log.dst}</td>
                                 <td className="p-1 text-purple-400">{log.app}</td>
                                 <td className={`p-1 font-bold ${log.action === 'ALLOW' ? 'text-green-500' : 'text-red-500'}`}>{log.action}</td>
                                 <td className="p-1 text-slate-400">{log.bytes} B</td>
                                 <td className="p-1 text-slate-500 italic max-w-xs truncate">{log.reason}</td>
                              </tr>
                           ))}
                        </tbody>
                     </table>
                  </div>
               </div>
            </div>

            {/* Commit Button (Floating) */}
            <div className="absolute bottom-28 right-6">
               <button 
                  onClick={startCommit}
                  disabled={gameState !== 'idle'}
                  className={`flex items-center gap-2 px-6 py-3 rounded-sm shadow-xl font-bold text-sm transition-all
                     ${gameState === 'idle' ? 'bg-orange-600 hover:bg-orange-500 text-white hover:scale-105' : 'bg-slate-700 text-slate-500 cursor-not-allowed'}`}
               >
                  <Save size={16} /> {gameState === 'committing' ? 'Committing...' : 'Commit'}
               </button>
            </div>

         </div>
      </div>
    </div>
  );
}