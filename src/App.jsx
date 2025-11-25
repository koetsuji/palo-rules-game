import React, { useState, useEffect } from 'react';
import { Shield, Server, Globe, Play, RefreshCw, AlertTriangle, CheckCircle, Database, Laptop, Wifi, ArrowRight, ArrowDown, Lock, FileText, Activity, Save, Search, Eye, Zap, X } from 'lucide-react';

// --- Game Constants ---
const ZONES = {
  trust: { id: 'trust', label: 'Trust-L3', color: 'emerald', ip: '10.1.1.0/24' },
  untrust: { id: 'untrust', label: 'Untrust-L3', color: 'blue', ip: '0.0.0.0/0' },
  dmz: { id: 'dmz', label: 'DMZ-L3', color: 'purple', ip: '192.168.50.0/24' },
  guest: { id: 'guest', label: 'Guest-L3', color: 'yellow', ip: '172.16.0.0/24' }
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

const PROFILES = [
  { id: 'none', label: 'None' },
  { id: 'default', label: 'Default (AV+Vuln)' },
  { id: 'strict', label: 'Strict (URL+Wildfire)' }
];

const LEVELS = [
  {
    id: 1,
    title: "Secure Internet Access",
    desc: "Users in Trust need to browse secure websites. Policy requires basic Antivirus protection.",
    packet: { srcZone: 'trust', dstZone: 'untrust', srcIp: '10.1.1.55', dstIp: '142.250.1.1', proto: 'TCP/443', app: 'ssl' },
    solution: { srcZone: 'trust', dstZone: 'untrust', app: 'ssl', service: 'application-default', action: 'ALLOW', nat: 'SNAT', profile: 'default' },
    hint: "Zone: Trust->Untrust. App: ssl. NAT: SNAT. Profile: Default (for AV)."
  },
  {
    id: 2,
    title: "Publishing DMZ Web Server",
    desc: "Public internet users need to access our Company Portal hosted in the DMZ.",
    packet: { srcZone: 'untrust', dstZone: 'dmz', srcIp: '203.0.113.50', dstIp: '203.0.113.1', proto: 'TCP/80', app: 'web-browsing' },
    solution: { srcZone: 'untrust', dstZone: 'dmz', app: 'web-browsing', service: 'application-default', action: 'ALLOW', nat: 'DNAT', profile: 'default' },
    hint: "Inbound traffic needs DNAT to find the internal server IP."
  },
  {
    id: 3,
    title: "Block Non-Standard SSH",
    desc: "An internal developer is trying to SSH to a server in the DMZ using a non-standard high port (2222).",
    packet: { srcZone: 'trust', dstZone: 'dmz', srcIp: '10.1.1.100', dstIp: '192.168.50.5', proto: 'TCP/2222', app: 'ssh' },
    solution: { srcZone: 'trust', dstZone: 'dmz', app: 'ssh', service: 'application-default', action: 'ALLOW', nat: 'NONE', profile: 'none' },
    specialCheck: (userConfig) => {
      if (userConfig.service === 'application-default') return { success: false, msg: "DROPPED: App-ID 'ssh' on port 2222 contradicts 'application-default' (Port 22). Good job enforcing standards!" };
      if (userConfig.service === 'any') return { success: true, msg: "WARNING: You allowed SSH on a non-standard port. It works, but violates security best practice." };
      return { success: false, msg: "Configuration mismatch." };
    },
    hint: "Use 'application-default' service to force standard ports. The packet should naturally drop."
  },
  {
    id: 4,
    title: "The Hairpin (U-Turn) NAT",
    desc: "An internal user (Trust) is trying to access the DMZ Web Server via its PUBLIC IP.",
    packet: { srcZone: 'trust', dstZone: 'untrust', srcIp: '10.1.1.50', dstIp: '203.0.113.1', proto: 'TCP/80', app: 'web-browsing' },
    solution: { srcZone: 'trust', dstZone: 'untrust', app: 'web-browsing', service: 'application-default', action: 'ALLOW', nat: 'DNAT+SNAT', profile: 'default' },
    hint: "Requires DNAT (to find server) AND SNAT (so server replies to Firewall, not User)."
  },
  {
    id: 5,
    title: "Data Exfiltration Attempt",
    desc: "A compromised host in Guest is trying to tunnel data via DNS to a suspicious IP.",
    packet: { srcZone: 'guest', dstZone: 'untrust', srcIp: '172.16.0.99', dstIp: '1.2.3.4', proto: 'UDP/53', app: 'dns' },
    solution: { srcZone: 'guest', dstZone: 'untrust', app: 'dns', service: 'application-default', action: 'DENY', nat: 'NONE', profile: 'any' },
    hint: "This looks suspicious. Create a DENY rule."
  }
];

export default function FirewallNGFW() {
  const [levelIdx, setLevelIdx] = useState(0);
  const [showOnboarding, setShowOnboarding] = useState(true);
  const [gameState, setGameState] = useState('idle');
  const [logs, setLogs] = useState([]);
  const [commitProgress, setCommitProgress] = useState(0);
  const [selectedLog, setSelectedLog] = useState(null);

  // Animation State
  const [packetCoords, setPacketCoords] = useState({ x: 50, y: 50, opacity: 0, color: 'bg-white', label: '' });

  // Policy State
  const [ruleName, setRuleName] = useState('Rule-1');
  const [srcZone, setSrcZone] = useState('trust');
  const [dstZone, setDstZone] = useState('untrust');
  const [app, setApp] = useState('any');
  const [service, setService] = useState('application-default');
  const [profile, setProfile] = useState('none');
  const [action, setAction] = useState('ALLOW');
  const [natType, setNatType] = useState('NONE');

  const level = LEVELS[levelIdx];

  // Coordinates tuned for the Grid Layout (Left box center ~17%, Right box center ~83%)
  const getZoneCoords = (zoneId) => {
    switch (zoneId) {
      case 'trust': return { x: 17, y: 25 };
      case 'untrust': return { x: 83, y: 25 };
      case 'guest': return { x: 17, y: 75 };
      case 'dmz': return { x: 83, y: 75 };
      case 'firewall': return { x: 50, y: 50 };
      default: return { x: 50, y: 50 };
    }
  };

  const startCommit = () => {
    setGameState('committing');
    setCommitProgress(0);
    const start = getZoneCoords(level.packet.srcZone);
    setPacketCoords({ ...start, opacity: 0, color: 'bg-white', label: level.packet.proto });

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

    // 1. Appear at Source
    setPacketCoords({ ...start, opacity: 1, color: 'bg-yellow-400', label: level.packet.srcIp });

    // 2. Move to Firewall
    setTimeout(() => {
      setPacketCoords(prev => ({ ...prev, x: fw.x, y: fw.y }));
    }, 500); // Slightly slower for dramatic effect

    // 3. Process & TRANSFORM (Visual NAT)
    setTimeout(() => {
      let nextColor = 'bg-yellow-400';
      let nextLabel = level.packet.srcIp;

      if (action === 'ALLOW') {
        if (natType === 'SNAT') {
          nextColor = 'bg-orange-500';
          nextLabel = 'NAT: 203.0.113.1';
        } else if (natType === 'DNAT') {
          nextColor = 'bg-purple-500';
          nextLabel = `NAT: ${level.packet.srcIp}`;
        } else if (natType === 'DNAT+SNAT') {
          nextColor = 'bg-purple-500 border-2 border-orange-500';
          nextLabel = 'U-TURN NAT';
        }
      }

      setPacketCoords(prev => ({ ...prev, color: nextColor, label: nextLabel }));
      evaluateTraffic(end);
    }, 1500);
  };

  const evaluateTraffic = (endCoords) => {
    const config = { srcZone, dstZone, app, service, action, nat: natType, profile };
    let finalAction = 'drop';
    let resultMsg = "";
    let isWin = false;
    let logicPassed = true;

    if (level.specialCheck) {
      const res = level.specialCheck(config);
      if (res.msg.includes("DROPPED") || res.msg.includes("WARNING")) {
        handleResult(true, res.msg, 'drop');
        setPacketCoords(prev => ({ ...prev, opacity: 0 }));
        return;
      }
    }

    if (srcZone !== level.packet.srcZone || dstZone !== level.packet.dstZone) { logicPassed = false; resultMsg = "Zone Mismatch"; }
    else if (app !== 'any' && app !== level.packet.app) { logicPassed = false; resultMsg = "App-ID Mismatch"; }
    else if (action !== level.solution.action) { logicPassed = false; resultMsg = "Action Mismatch"; }
    else if (action === 'ALLOW' && natType !== level.solution.nat) { logicPassed = false; resultMsg = "NAT Mismatch"; }
    else if (action === 'ALLOW' && level.solution.profile && profile !== level.solution.profile && profile !== 'strict') {
      logicPassed = false;
      resultMsg = "Security Profile Missing! (Threat inspection required)";
    }

    if (logicPassed) {
      isWin = true;
      resultMsg = "Traffic Allowed";
      finalAction = action === 'DENY' ? 'drop' : 'allow';
    } else {
      isWin = false;
      if (!resultMsg) resultMsg = "Incorrect Configuration";
      finalAction = 'drop';
    }

    if (finalAction === 'allow' && isWin) {
      setPacketCoords(prev => ({ ...prev, x: endCoords.x, y: endCoords.y }));
      setTimeout(() => handleResult(true, resultMsg, 'allow'), 1000);
    } else {
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
      reason: reason,
      flags: action === 'allow' ? '0x00' : '0xBAD',
      country: 'US -> US'
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
      setProfile('none');
      setPacketCoords({ x: 50, y: 50, opacity: 0, color: 'bg-white', label: '' });
    } else {
      alert("PCNSE Certification Achieved! All scenarios complete.");
      setLevelIdx(0);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 font-sans flex flex-col relative">

      {/* Interactive Log Modal */}
      {selectedLog && (
        <div className="absolute inset-0 z-[60] bg-black/80 flex items-center justify-center p-4 animate-in fade-in backdrop-blur-sm">
          <div className="bg-slate-800 rounded-lg shadow-2xl border border-slate-600 w-full max-w-2xl overflow-hidden">
            <div className="bg-slate-900 p-4 border-b border-slate-700 flex justify-between items-center">
              <h3 className="font-bold text-white flex items-center gap-2"><Search size={18} className="text-orange-500" /> Traffic Log Detail</h3>
              <button onClick={() => setSelectedLog(null)} className="text-slate-400 hover:text-white">Close</button>
            </div>
            <div className="p-6 grid grid-cols-2 gap-6 text-sm font-mono">
              <div className="space-y-2">
                <div className="text-slate-500 text-xs uppercase">Source</div>
                <div className="text-emerald-400 text-lg">{selectedLog.src}</div>
              </div>
              <div className="space-y-2">
                <div className="text-slate-500 text-xs uppercase">Destination</div>
                <div className="text-blue-400 text-lg">{selectedLog.dst}</div>
              </div>
              <div className="col-span-2 border-t border-slate-700 pt-4 space-y-2">
                <div className="grid grid-cols-4 gap-4">
                  <div><div className="text-slate-500 text-xs">App</div><div className="text-purple-400">{selectedLog.app}</div></div>
                  <div><div className="text-slate-500 text-xs">Action</div><div className={selectedLog.action === 'ALLOW' ? 'text-green-500' : 'text-red-500'}>{selectedLog.action}</div></div>
                  <div><div className="text-slate-500 text-xs">Bytes</div><div className="text-white">{selectedLog.bytes}</div></div>
                  <div><div className="text-slate-500 text-xs">Flags</div><div className="text-white">{selectedLog.flags}</div></div>
                </div>
              </div>
              <div className="col-span-2 bg-black/30 p-3 rounded border border-slate-700">
                <div className="text-slate-500 text-xs mb-1">Reason</div>
                <div className="text-orange-300">{selectedLog.reason}</div>
              </div>
            </div>
          </div>
        </div>
      )}

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
          <div className="flex flex-col items-end"><span className="text-slate-500">DEVICE</span><span className="text-emerald-400">PA-3220-HQ</span></div>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-12 overflow-hidden relative">

        {/* Left Sidebar */}
        <div className="col-span-2 bg-slate-900 border-r border-slate-800 flex flex-col py-4 z-40">
          <div className="px-4 mb-6">
            <div className="text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">Dashboard</div>
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-slate-300 bg-slate-800 px-3 py-2 rounded cursor-pointer border-l-2 border-orange-500"><Activity size={14} /> Monitor</div>
              <div className="flex items-center gap-2 text-slate-400 px-3 py-2 hover:text-slate-200 cursor-pointer"><Lock size={14} /> Policies</div>
              <div className="flex items-center gap-2 text-slate-400 px-3 py-2 hover:text-slate-200 cursor-pointer"><Globe size={14} /> Network</div>
            </div>
          </div>
          <div className="px-4 mt-auto">
            <div className="bg-slate-800 rounded p-3 border border-slate-700">
              <h3 className="text-xs font-bold text-orange-500 mb-1">Incident #{2040 + levelIdx}</h3>
              <p className="text-[10px] text-slate-400 leading-tight mb-2">{level.desc}</p>
              <div className="pt-2 border-t border-slate-700 grid grid-cols-1 gap-1 text-[9px] font-mono">
                <div className="flex justify-between"><span className="text-slate-500">SRC:</span> <span className="text-white">{level.packet.srcIp}</span></div>
                <div className="flex justify-between"><span className="text-slate-500">DST:</span> <span className="text-white">{level.packet.dstIp}</span></div>
              </div>
            </div>
          </div>
        </div>

        {/* Center: Visualizer & Editor */}
        <div className="col-span-10 bg-slate-950 flex flex-col relative">

          {/* --- VISUALIZER (Restored Grid Layout) --- */}
          <div className="h-1/2 border-b border-slate-800 relative bg-[#0B1120] overflow-hidden p-8">

            {/* Background Grid Pattern */}
            <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'radial-gradient(#475569 1px, transparent 1px)', backgroundSize: '20px 20px' }}></div>

            {/* Commit Overlay */}
            {gameState === 'committing' && (
              <div className="absolute inset-0 bg-slate-950/80 z-50 flex flex-col items-center justify-center backdrop-blur-sm">
                <div className="w-64 bg-slate-800 rounded-full h-2 mb-4 overflow-hidden"><div className="bg-orange-500 h-full transition-all duration-200 ease-out" style={{ width: `${commitProgress}%` }}></div></div>
                <div className="text-orange-500 font-mono text-sm animate-pulse">Committing...</div>
              </div>
            )}

            {/* Animated Packet Layer (On Top) */}
            <div
              className="absolute z-30 transition-all duration-500 linear flex flex-col items-center justify-center pointer-events-none"
              style={{ left: `${packetCoords.x}%`, top: `${packetCoords.y}%`, opacity: packetCoords.opacity, transform: 'translate(-50%, -50%)' }}
            >
              <div className={`w-8 h-8 rounded-full shadow-xl flex items-center justify-center relative ${packetCoords.color}`}>
                <div className={`absolute inset-0 rounded-full animate-ping opacity-75 ${packetCoords.color}`}></div>
                {level.packet.app === 'ssl' ? <Lock size={14} className="text-black" /> : level.packet.app === 'dns' ? <Globe size={14} className="text-black" /> : <FileText size={14} className="text-black" />}
              </div>
              <div className="mt-2 bg-black/90 text-white text-[10px] px-2 py-1 rounded border border-slate-600 whitespace-nowrap font-mono shadow-lg transform -translate-x-1/2 left-1/2 absolute top-full">
                {packetCoords.label}
              </div>
            </div>

            {/* Grid Layout for Zones */}
            <div className="w-full h-full grid grid-cols-3 gap-8">

              {/* Left Column: Trust & Guest */}
              <div className="flex flex-col gap-6 h-full">
                {/* Trust */}
                <div className={`flex-1 border-2 border-dashed rounded-2xl p-4 relative transition-all duration-500 ${level.packet.srcZone === 'trust' ? 'border-emerald-500 bg-emerald-900/20 shadow-[0_0_30px_rgba(16,185,129,0.15)]' : 'border-slate-700 bg-slate-900/40'}`}>
                  <div className="flex items-center gap-2 text-emerald-500 font-bold text-sm uppercase tracking-wider"><Laptop size={16} /> Trust-L3</div>
                  <div className="text-[10px] text-emerald-700/70 font-mono mt-1">10.1.1.0/24</div>
                  <div className="absolute bottom-3 right-3 opacity-10"><Laptop size={64} /></div>
                </div>
                {/* Guest */}
                <div className={`flex-1 border-2 border-dashed rounded-2xl p-4 relative transition-all duration-500 ${level.packet.srcZone === 'guest' ? 'border-yellow-500 bg-yellow-900/20 shadow-[0_0_30px_rgba(234,179,8,0.15)]' : 'border-slate-700 bg-slate-900/40'}`}>
                  <div className="flex items-center gap-2 text-yellow-500 font-bold text-sm uppercase tracking-wider"><Wifi size={16} /> Guest-L3</div>
                  <div className="text-[10px] text-yellow-700/70 font-mono mt-1">172.16.0.0/24</div>
                  <div className="absolute bottom-3 right-3 opacity-10"><Wifi size={64} /></div>
                </div>
              </div>

              {/* Center Column: Firewall */}
              <div className="flex items-center justify-center relative">
                {/* Connecting Lines */}
                <div className="absolute w-full h-1 bg-slate-800 top-1/4 -z-10"></div> {/* Trust -> Untrust Path */}
                <div className="absolute w-full h-1 bg-slate-800 bottom-1/4 -z-10"></div> {/* Guest -> DMZ Path */}
                <div className="absolute h-full w-1 bg-slate-800 left-1/2 -z-10"></div> {/* Vertical Path */}

                <div className="w-48 h-48 bg-slate-800 rounded-xl border-2 border-orange-500 shadow-[0_0_60px_rgba(249,115,22,0.25)] flex flex-col items-center justify-center z-20 relative">
                  <Shield size={56} className="text-orange-500 mb-3 filter drop-shadow-lg" />
                  <div className="text-xs font-bold text-white tracking-widest">PA-3220</div>
                  <div className="text-[9px] text-slate-400 font-mono mt-1">203.0.113.1</div>
                  {/* Interfaces */}
                  <div className="absolute top-8 -left-3 bg-slate-900 border border-slate-600 text-[9px] text-emerald-500 px-1 rounded">eth1/2</div>
                  <div className="absolute top-8 -right-3 bg-slate-900 border border-slate-600 text-[9px] text-blue-500 px-1 rounded">eth1/1</div>
                  <div className="absolute bottom-8 -left-3 bg-slate-900 border border-slate-600 text-[9px] text-yellow-500 px-1 rounded">eth1/4</div>
                  <div className="absolute bottom-8 -right-3 bg-slate-900 border border-slate-600 text-[9px] text-purple-500 px-1 rounded">eth1/3</div>
                </div>
              </div>

              {/* Right Column: Untrust & DMZ */}
              <div className="flex flex-col gap-6 h-full">
                {/* Untrust */}
                <div className={`flex-1 border-2 border-dashed rounded-2xl p-4 relative transition-all duration-500 ${level.packet.dstZone === 'untrust' ? 'border-blue-500 bg-blue-900/20 shadow-[0_0_30px_rgba(59,130,246,0.15)]' : 'border-slate-700 bg-slate-900/40'}`}>
                  <div className="flex items-center gap-2 text-blue-500 font-bold text-sm uppercase tracking-wider justify-end">Untrust-L3 <Globe size={16} /></div>
                  <div className="text-[10px] text-blue-700/70 font-mono mt-1 text-right">0.0.0.0/0</div>
                  <div className="absolute bottom-3 left-3 opacity-10"><Globe size={64} /></div>
                </div>
                {/* DMZ */}
                <div className={`flex-1 border-2 border-dashed rounded-2xl p-4 relative transition-all duration-500 ${level.packet.dstZone === 'dmz' ? 'border-purple-500 bg-purple-900/20 shadow-[0_0_30px_rgba(168,85,247,0.15)]' : 'border-slate-700 bg-slate-900/40'}`}>
                  <div className="flex items-center gap-2 text-purple-500 font-bold text-sm uppercase tracking-wider justify-end">DMZ-L3 <Server size={16} /></div>
                  <div className="text-[10px] text-purple-700/70 font-mono mt-1 text-right">192.168.50.0/24</div>
                  <div className="absolute bottom-3 left-3 opacity-10"><Server size={64} /></div>
                </div>
              </div>

            </div>

            {/* Results Overlay */}
            {(gameState === 'success' || gameState === 'failure') && (
              <div className="absolute inset-0 z-50 bg-slate-950/90 flex items-center justify-center animate-in fade-in zoom-in duration-300">
                <div className={`p-8 rounded-xl border shadow-2xl max-w-md text-center backdrop-blur-md ${gameState === 'success' ? 'border-emerald-500 bg-emerald-950/50' : 'border-red-500 bg-red-950/50'}`}>
                  {gameState === 'success' ? <CheckCircle className="w-16 h-16 text-emerald-500 mx-auto mb-4" /> : <AlertTriangle className="w-16 h-16 text-red-500 mx-auto mb-4" />}
                  <h3 className="text-2xl font-bold text-white mb-2">{gameState === 'success' ? "TRAFFIC ALLOWED" : "POLICY BLOCKED"}</h3>
                  <p className="text-sm text-slate-300 mb-8 leading-relaxed">{logs[0]?.reason}</p>
                  {gameState === 'success' ? (
                    <button onClick={nextLevel} className="bg-emerald-600 hover:bg-emerald-500 text-white px-8 py-3 rounded-lg font-bold flex items-center gap-2 mx-auto transition-all hover:scale-105">Next Scenario <ArrowRight size={18} /></button>
                  ) : (
                    <button onClick={() => setGameState('idle')} className="bg-slate-700 hover:bg-slate-600 text-white px-8 py-3 rounded-lg font-bold flex items-center gap-2 mx-auto"><RefreshCw size={18} /> Reconfigure</button>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* --- EDITOR --- */}
          <div className="h-1/2 flex flex-col bg-slate-900">
            <div className="bg-slate-900 border-b border-slate-800 flex px-4 shadow-md z-10">
              <div className="px-4 py-3 text-xs font-bold text-orange-500 border-b-2 border-orange-500 bg-slate-800/50">Security Policy</div>
              <div className="px-4 py-3 text-xs font-bold text-slate-500">NAT</div>
            </div>

            <div className="p-4 overflow-auto flex-1 bg-slate-900/50 relative">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="text-[10px] text-slate-500 font-bold uppercase border-b border-slate-700">
                    <th className="p-2">Name</th>
                    <th className="p-2">Source</th>
                    <th className="p-2">Dest</th>
                    <th className="p-2">App</th>
                    <th className="p-2">Service</th>
                    <th className="p-2">Action</th>
                    <th className="p-2 text-orange-400">Profile</th>
                    <th className="p-2 text-blue-400">NAT</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="bg-slate-800 text-xs border-l-4 border-orange-500 shadow-sm">
                    <td className="p-2"><input value={ruleName} onChange={(e) => setRuleName(e.target.value)} className="bg-transparent text-white w-20 outline-none" /></td>
                    <td className="p-2"><select value={srcZone} onChange={(e) => setSrcZone(e.target.value)} className="bg-slate-900 border border-slate-600 rounded p-1 text-[10px] w-20 text-emerald-400" disabled={gameState !== 'idle'}>{Object.values(ZONES).map(z => <option key={z.id} value={z.id}>{z.label}</option>)}</select></td>
                    <td className="p-2"><select value={dstZone} onChange={(e) => setDstZone(e.target.value)} className="bg-slate-900 border border-slate-600 rounded p-1 text-[10px] w-20 text-blue-400" disabled={gameState !== 'idle'}>{Object.values(ZONES).map(z => <option key={z.id} value={z.id}>{z.label}</option>)}</select></td>
                    <td className="p-2"><select value={app} onChange={(e) => setApp(e.target.value)} className="bg-slate-900 border border-slate-600 rounded p-1 text-[10px] w-20" disabled={gameState !== 'idle'}>{APPS.map(a => <option key={a.id} value={a.id}>{a.label}</option>)}</select></td>
                    <td className="p-2"><select value={service} onChange={(e) => setService(e.target.value)} className="bg-slate-900 border border-slate-600 rounded p-1 text-[10px] w-24" disabled={gameState !== 'idle'}>{SERVICES.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}</select></td>
                    <td className="p-2"><select value={action} onChange={(e) => setAction(e.target.value)} className={`border rounded p-1 text-[10px] w-16 font-bold ${action === 'ALLOW' ? 'bg-emerald-900 border-emerald-700 text-emerald-400' : 'bg-red-900 border-red-700 text-red-400'}`} disabled={gameState !== 'idle'}><option value="ALLOW">Allow</option><option value="DENY">Deny</option></select></td>
                    <td className="p-2"><select value={profile} onChange={(e) => setProfile(e.target.value)} className="bg-slate-900 border border-orange-900/50 text-orange-400 rounded p-1 text-[10px] w-20" disabled={gameState !== 'idle'}>{PROFILES.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}</select></td>
                    <td className="p-2"><select value={natType} onChange={(e) => setNatType(e.target.value)} className="bg-slate-900 border border-blue-900/50 text-blue-400 rounded p-1 text-[10px] w-20" disabled={gameState !== 'idle'}><option value="NONE">None</option><option value="SNAT">SNAT</option><option value="DNAT">DNAT</option><option value="DNAT+SNAT">U-Turn</option></select></td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Interactive Logs */}
            <div className="h-32 bg-slate-950 border-t border-slate-800 flex flex-col">
              <div className="px-3 py-1 bg-slate-900 text-[10px] text-slate-400 font-bold border-b border-slate-800">TRAFFIC LOGS (CLICK ROW FOR DETAILS)</div>
              <div className="overflow-auto flex-1">
                <table className="w-full text-left text-[10px] font-mono">
                  <thead className="sticky top-0 bg-slate-950 text-slate-500">
                    <tr><th className="p-1">Time</th><th className="p-1">Source</th><th className="p-1">Dest</th><th className="p-1">App</th><th className="p-1">Action</th></tr>
                  </thead>
                  <tbody>
                    {logs.map(log => (
                      <tr key={log.id} onClick={() => setSelectedLog(log)} className="border-b border-slate-800 hover:bg-slate-800 cursor-pointer transition-colors group">
                        <td className="p-1 text-slate-500 group-hover:text-white">{log.time}</td>
                        <td className="p-1 text-emerald-400">{log.src}</td>
                        <td className="p-1 text-blue-400">{log.dst}</td>
                        <td className="p-1 text-purple-400 flex items-center gap-1">{log.app}</td>
                        <td className={`p-1 font-bold ${log.action === 'ALLOW' ? 'text-green-500' : 'text-red-500'}`}>{log.action} <Eye size={8} className="inline ml-1 opacity-0 group-hover:opacity-100" /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <div className="absolute bottom-36 right-6 z-50">
            <button onClick={startCommit} disabled={gameState !== 'idle'} className={`flex items-center gap-2 px-6 py-4 rounded-lg shadow-2xl font-bold text-sm transition-all transform ${gameState === 'idle' ? 'bg-orange-600 hover:bg-orange-500 text-white hover:scale-105' : 'bg-slate-700 text-slate-500 cursor-not-allowed'}`}>
              <Save size={18} /> {gameState === 'committing' ? 'Committing...' : 'Commit Changes'}
            </button>
          </div>

        </div>
      </div>
      {/* Onboarding Modal */}
      {showOnboarding && (
        <div className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center animate-in fade-in duration-300">
          {/* Arrow pointing to tickets */}
          {/* Arrow pointing to tickets */}
          <div className="absolute bottom-[15%] left-[5%] z-20 flex flex-col items-center animate-bounce hidden md:flex">
            <div className="text-orange-500 font-bold font-mono mb-2 text-lg shadow-black drop-shadow-md">TICKETS HERE</div>
            <ArrowDown size={64} className="text-orange-500 filter drop-shadow-lg" />
          </div>

          <div className="bg-slate-800 border border-slate-600 p-8 rounded-2xl shadow-2xl max-w-lg relative z-10 mx-4">
            <button onClick={() => setShowOnboarding(false)} className="absolute top-4 right-4 text-slate-400 hover:text-white transition-colors">
              <X size={24} />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="bg-orange-600 p-2 rounded-lg">
                <Shield size={28} className="text-white" />
              </div>
              <h2 className="text-2xl font-bold text-white">Welcome, Network Admin</h2>
            </div>

            <div className="space-y-4 text-slate-300 leading-relaxed">
              <p>
                You're a Network/IT Admin, and there are incoming tickets on the <span className="text-orange-400 font-bold">down left corner</span> of the page.
              </p>
              <p>
                You need to configure new firewall rules to resolve these tickets. Analyze the traffic, set the correct Source, Destination, and Actions, and keep the network secure!
              </p>
            </div>

            <div className="mt-8 flex justify-end">
              <button
                onClick={() => setShowOnboarding(false)}
                className="bg-orange-600 hover:bg-orange-500 text-white px-6 py-3 rounded-lg font-bold shadow-lg hover:shadow-orange-500/20 transition-all transform hover:-translate-y-1"
              >
                Let's Start
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}