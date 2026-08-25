import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  HardDrive, 
  FileText, 
  Server, 
  Play, 
  Search, 
  ArrowRight,
  Layers,
  ChevronRight,
  Radio,
  Wifi,
  Power,
  Lock,
  KeyRound
} from 'lucide-react';

import { dummyDevices, dummyJobs } from './dummyData';

export default function App() {
  const [view, setView] = useState('landing'); // 'landing', 'booting', or 'dashboard'
  const [bootStep, setBootStep] = useState(0);
  const [activeTab, setActiveTab] = useState('overview');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [networkPulse, setNetworkPulse] = useState(0);

  // Simulated live telemetry loop for networking wire and stack animation
  useEffect(() => {
    const int = setInterval(() => setNetworkPulse(p => (p + 1) % 100), 2000);
    return () => clearInterval(int);
  }, []);

  // Boot sequence effect when clicking Start Application
  const handleStartApp = () => {
    setView('booting');
    setBootStep(1);
    setTimeout(() => setBootStep(2), 700);
    setTimeout(() => setBootStep(3), 1400);
    setTimeout(() => setBootStep(4), 2100);
    setTimeout(() => setView('dashboard'), 2800);
  };

  const [devices, setDevices] = useState(dummyDevices);
  const [jobs, setJobs] = useState(dummyJobs);

  const [selectedCert, setSelectedCert] = useState(null);
  const [recoveryResults, setRecoveryResults] = useState(null);
  const [toast, setToast] = useState('');

  // ── Wipe Confirmation Modal State ──
  const [wipeConfirmModal, setWipeConfirmModal] = useState(null); // { jobId, deviceId, deviceName, type, capacity, method, tech }
  const [wipeConfirmStep, setWipeConfirmStep] = useState(1);      // 1=review, 2=PIN
  const [wipeTypedText, setWipeTypedText] = useState('');
  const [wipePin, setWipePin] = useState('');
  const [wipeError, setWipeError] = useState('');

  // ── Recovery Confirmation Modal State ──
  const [recoveryConfirmModal, setRecoveryConfirmModal] = useState(null); // { deviceId, deviceName }
  const [pendingRecoveryAction, setPendingRecoveryAction] = useState(null); // async fn to call on confirm

  const triggerToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(''), 3500);
  };

  const handleDispatchJob = (jobId) => {
    setJobs(jobs.map(j => j.jobId === jobId ? { ...j, status: 'COMPLETE', cert: `CERT-${Math.floor(1000 + Math.random() * 9000)}-X9Z` } : j));
    setDevices(devices.map(d => d.currentJob === jobId ? { ...d, status: 'COMPLETE' } : d));
    triggerToast(`Job ${jobId} successfully executed and cryptographic certificate generated!`);
  };

  const handleQuarantineDevice = (deviceId) => {
    setDevices(devices.map(d => d.id === deviceId ? { ...d, status: 'QUARANTINED' } : d));
    triggerToast(`Device ${deviceId} moved to physical shredding quarantine.`);
  };

  // ── Open the 3-step wipe confirmation modal ──
  const openWipeConfirmation = (job) => {
    const dev = devices.find(d => d.currentJob === job.jobId) || {};
    setWipeConfirmModal({
      jobId: job.jobId,
      deviceId: job.deviceId,
      deviceName: dev.name || job.deviceId,
      type: dev.type || 'Unknown',
      capacity: dev.capacity || 'N/A',
      method: job.method,
      tech: job.technician || 'ZT-OPERATOR-01'
    });
    setWipeConfirmStep(1);
    setWipeTypedText('');
    setWipePin('');
    setWipeError('');
  };

  const closeWipeConfirmation = () => {
    setWipeConfirmModal(null);
    setWipeConfirmStep(1);
    setWipeTypedText('');
    setWipePin('');
    setWipeError('');
  };

  const handleConfirmedWipe = async () => {
    if (!wipeConfirmModal) return;
    setWipeError('');
    try {
      const res = await fetch('/api/jobs/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_path: wipeConfirmModal.deviceId,
          method: wipeConfirmModal.method,
          operator_id: wipeConfirmModal.tech,
          typed_confirmation: wipeTypedText,
          security_pin: wipePin
        })
      });
      if (!res.ok) {
        const err = await res.json();
        setWipeError(err.detail?.message || 'Authorization failed.');
        return;
      }
      // Success — update local UI state
      handleDispatchJob(wipeConfirmModal.jobId);
      closeWipeConfirmation();
    } catch (e) {
      setWipeError('Network error: ' + e.message);
    }
  };

  // ── Open the lightweight recovery confirmation modal ──
  const openRecoveryConfirmation = (deviceId, deviceName, actionFn) => {
    setRecoveryConfirmModal({ deviceId, deviceName });
    setPendingRecoveryAction(() => actionFn);
  };

  const closeRecoveryConfirmation = () => {
    setRecoveryConfirmModal(null);
    setPendingRecoveryAction(null);
  };

  const filteredJobs = jobs.filter(j => {
    const matchesSearch = j.jobId.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          j.deviceId.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          j.method.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterStatus === 'ALL' || j.status === filterStatus;
    return matchesSearch && matchesFilter;
  });

  if (view === 'booting') {
    return (
      <div className="min-h-screen bg-black text-white font-mono flex flex-col items-center justify-center p-6 selection:bg-white selection:text-black">
        <div className="max-w-md w-full border border-zinc-800 p-8 bg-zinc-950 shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-zinc-900 border border-zinc-700 animate-spin">
              <Power className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-sm font-bold uppercase tracking-widest text-white">Initializing SanitizeCore™</h2>
              <p className="text-[10px] text-zinc-500">Secure Node Wire Stack v4.2</p>
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <div className={`flex items-center justify-between p-2.5 border ${bootStep >= 1 ? 'border-white bg-zinc-900 text-white' : 'border-zinc-900 text-zinc-600'}`}>
              <span>[01] Verifying NIST 800-88 compliance rules</span>
              <span>{bootStep >= 1 ? 'OK' : 'WAIT'}</span>
            </div>
            <div className={`flex items-center justify-between p-2.5 border ${bootStep >= 2 ? 'border-white bg-zinc-900 text-white' : 'border-zinc-900 text-zinc-600'}`}>
              <span>[02] Establishing wire telemetry node links</span>
              <span>{bootStep >= 2 ? 'OK' : 'WAIT'}</span>
            </div>
            <div className={`flex items-center justify-between p-2.5 border ${bootStep >= 3 ? 'border-white bg-zinc-900 text-white' : 'border-zinc-900 text-zinc-600'}`}>
              <span>[03] Loading cryptographic key vault</span>
              <span>{bootStep >= 3 ? 'SECURE' : 'WAIT'}</span>
            </div>
            <div className={`flex items-center justify-between p-2.5 border ${bootStep >= 4 ? 'border-white bg-zinc-900 text-white' : 'border-zinc-900 text-zinc-600'}`}>
              <span>[04] Launching master console interface</span>
              <span>{bootStep >= 4 ? 'READY' : 'WAIT'}</span>
            </div>
          </div>
          
          <div className="mt-6 w-full bg-zinc-900 h-1.5 overflow-hidden">
            <div className="bg-white h-full transition-all duration-700" style={{ width: `${(bootStep / 4) * 100}%` }}></div>
          </div>
        </div>
      </div>
    );
  }

  if (view === 'landing') {
    return (
      <div className="min-h-screen bg-black text-white font-sans flex flex-col selection:bg-white selection:text-black overflow-x-hidden relative">
        
        {/* Toast Notification */}
        {toast && (
          <div className="fixed top-5 right-5 z-50 bg-white text-black font-semibold px-4 py-3 rounded-none shadow-2xl flex items-center gap-3 border border-white animate-bounce">
            <ShieldCheck className="w-5 h-5 flex-shrink-0" />
            <span>{toast}</span>
          </div>
        )}

        {/* Background Animated SVG Networking Wires in Black & White */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-30">
          <svg className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="wireGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ffffff" />
                <stop offset="50%" stopColor="#666666" />
                <stop offset="100%" stopColor="#ffffff" />
              </linearGradient>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>
            {/* Network Grid Lines */}
            <path d="M 0,100 Q 300,50 600,200 T 1200,150" fill="none" stroke="url(#wireGrad)" strokeWidth="1.5" filter="url(#glow)" />
            <path d="M 100,0 Q 400,300 800,100 T 1400,400" fill="none" stroke="url(#wireGrad)" strokeWidth="1" opacity="0.6" />
            <path d="M 50,500 Q 500,200 900,600 T 1500,300" fill="none" stroke="url(#wireGrad)" strokeWidth="1.5" filter="url(#glow)" />
            
            {/* Animated Highlighted White Dots along Wires */}
            <circle cx={(networkPercentage => (networkPercentage * 14) % 1200)(networkPulse)} cy="150" r="5" fill="#ffffff" className="animate-pulse shadow-lg" filter="url(#glow)" />
            <circle cx={(networkPercentage => 1200 - ((networkPercentage * 18) % 1200))(networkPulse)} cy="320" r="5.5" fill="#ffffff" filter="url(#glow)" />
            <circle cx={(networkPercentage => (networkPercentage * 10) % 1400)(networkPulse)} cy="450" r="4.5" fill="#ffffff" filter="url(#glow)" />
            <circle cx={(networkPercentage => (networkPercentage * 12) % 1100)(networkPulse)} cy="220" r="4" fill="#dddddd" />
          </svg>
        </div>

        {/* Navbar */}
        <header className="border-b border-zinc-800 bg-black/80 backdrop-blur-md sticky top-0 z-40 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-zinc-900 border border-zinc-700 text-white">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-white uppercase">
                SanitizeCore™ AI
              </span>
              <p className="text-[10px] text-zinc-400 tracking-wider uppercase font-mono">Military-Grade Data Erasure & Wire Node Sync</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button 
              onClick={handleStartApp}
              className="bg-white hover:bg-zinc-200 text-black font-extrabold px-6 py-2.5 text-sm transition-all flex items-center gap-2 transform hover:-translate-y-0.5 shadow-2xl cursor-pointer"
            >
              <Power className="w-4 h-4" />
              <span>Start Application</span>
            </button>
          </div>
        </header>

        {/* Hero Section */}
        <section className="relative flex-1 flex flex-col items-center justify-center px-6 py-20 lg:py-28 text-center z-10">
          
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-zinc-900/40 rounded-full blur-3xl pointer-events-none"></div>

          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-zinc-900 border border-zinc-700 text-zinc-300 text-xs font-mono mb-6 uppercase tracking-widest">
            <Wifi className="w-3.5 h-3.5 text-white" /> NIST 800-88 & Network Node Stack Verified
          </div>

          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tight max-w-4xl text-white leading-[1.1] mb-6 uppercase">
            Absolute Data Erasure & <span className="text-zinc-400 underline decoration-white decoration-2">Node Wire Telemetry</span>
          </h1>

          <p className="text-base sm:text-lg text-zinc-400 max-w-2xl mb-10 leading-relaxed font-light">
            Eliminate corporate liability with tamper-evident sanitization audit logs, animated stack visualization, and instant cryptographic certificate generation across distributed node clusters.
          </p>

          <div className="flex flex-col sm:flex-row items-center gap-4 w-full justify-center max-w-md">
            <button 
              onClick={handleStartApp}
              className="w-full sm:w-auto bg-white hover:bg-zinc-200 text-black font-black px-8 py-4 transition-all flex items-center justify-center gap-3 group text-base uppercase tracking-wider shadow-2xl cursor-pointer"
            >
              <Power className="w-5 h-5" />
              <span>Start Application</span>
              <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </button>
            <a 
              href="#stacks"
              className="w-full sm:w-auto bg-zinc-900 hover:bg-zinc-800 text-zinc-300 font-bold px-6 py-4 border border-zinc-800 transition-all text-base flex items-center justify-center gap-2 uppercase tracking-wider"
            >
              <Layers className="w-4 h-4 text-white" /> View Node Stacks
            </a>
          </div>

          {/* Interactive Stack Visualizer Widget */}
          <div id="stacks" className="mt-20 max-w-4xl w-full bg-zinc-950 border border-zinc-800 p-6 sm:p-8 backdrop-blur-xl shadow-2xl relative overflow-hidden text-left">
            <div className="absolute top-0 right-0 p-8 text-zinc-700 font-mono text-xs uppercase tracking-widest pointer-events-none">
              Stack Layer Active // Node Cluster A
            </div>
            
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2.5 bg-zinc-900 border border-zinc-700 text-white">
                <Layers className="w-5 h-5 animate-spin" style={{ animationDuration: '12s' }} />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white uppercase tracking-wider">Distributed Sanitization Stack</h3>
                <p className="text-xs text-zinc-400 font-mono">Real-time wire synchronization across 6 connected storage nodes</p>
              </div>
            </div>

            {/* Stack Layers */}
            <div className="space-y-3">
              <div className="bg-black border border-zinc-700 p-4 flex items-center justify-between shadow-lg transform transition-all hover:border-white">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-white animate-ping"></div>
                  <div>
                    <h4 className="text-sm font-bold text-white uppercase">Layer 3: Cryptographic Key Destruction (SED / NVMe)</h4>
                    <p className="text-xs text-zinc-400">DEV-002, DEV-004 • Instant Opal 2.0 Key Wrapping</p>
                  </div>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 bg-zinc-900 text-white border border-zinc-700">Active Sync</span>
              </div>

              <div className="bg-black border border-zinc-800 p-4 flex items-center justify-between shadow-lg transform transition-all hover:border-zinc-500">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-zinc-400"></div>
                  <div>
                    <h4 className="text-sm font-bold text-white uppercase">Layer 2: NIST 800-88 Purge / Clear Protocol</h4>
                    <p className="text-xs text-zinc-400">DEV-001, DEV-003, DEV-006 • 3-pass sector sampling</p>
                  </div>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 bg-zinc-900 text-zinc-300 border border-zinc-800">Operational</span>
              </div>

              <div className="bg-black border border-zinc-800 p-4 flex items-center justify-between shadow-lg transform transition-all hover:border-zinc-500">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-zinc-600 animate-pulse"></div>
                  <div>
                    <h4 className="text-sm font-bold text-white uppercase">Layer 1: Anomaly Quarantine & Entropy Check</h4>
                    <p className="text-xs text-zinc-400">DEV-005 (USB) • Low entropy region detected (EVT-1008)</p>
                  </div>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 bg-zinc-900 text-zinc-400 border border-zinc-800">Quarantined</span>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-zinc-900 flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
                <Radio className="w-4 h-4 text-white animate-pulse" />
                <span>Wire Latency: <strong className="text-white">1.2ms</strong> • Packet Loss: <strong className="text-white">0.00%</strong></span>
              </div>
              <button 
                onClick={handleStartApp}
                className="bg-white hover:bg-zinc-200 text-black font-bold px-5 py-2.5 text-xs transition-all flex items-center gap-2 uppercase tracking-wider cursor-pointer"
              >
                <span>Launch Master Console</span>
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>

        </section>

        {/* Footer */}
        <footer className="border-t border-zinc-800 bg-black py-8 text-center text-xs text-zinc-500 z-10 font-mono uppercase tracking-widest">
          SanitizeCore™ Data Erasure & Compliance Audit Platform • August 24, 2026
        </footer>

      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white font-sans flex flex-col selection:bg-white selection:text-black">
      
      {/* Toast Notification */}
      {toast && (
        <div className="fixed top-5 right-5 z-50 bg-white text-black font-semibold px-4 py-3 shadow-2xl flex items-center gap-3 border border-white animate-bounce">
          <ShieldCheck className="w-5 h-5 flex-shrink-0" />
          <span>{toast}</span>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-950 backdrop-blur-md sticky top-0 z-40 px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => setView('landing')}>
          <div className="p-2.5 bg-zinc-900 border border-zinc-700 text-white">
            <Server className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase">
              Data Erasure & Compliance Dashboard
            </h1>
            <p className="text-xs text-zinc-400 font-mono">System Operations & Wire Stack Telemetry • August 24, 2026</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-zinc-900 p-1.5 border border-zinc-800">
            <button 
              onClick={() => setActiveTab('overview')}
              className={`px-4 py-2 text-sm font-medium transition-all uppercase tracking-wider cursor-pointer ${activeTab === 'overview' ? 'bg-white text-black font-bold shadow-md' : 'text-zinc-400 hover:text-white'}`}
            >
              Dashboard Overview
            </button>
            <button 
              onClick={() => setActiveTab('jobs')}
              className={`px-4 py-2 text-sm font-medium transition-all uppercase tracking-wider cursor-pointer ${activeTab === 'jobs' ? 'bg-white text-black font-bold shadow-md' : 'text-zinc-400 hover:text-white'}`}
            >
              Jobs & Verification
            </button>
            <button 
              onClick={() => setActiveTab('devices')}
              className={`px-4 py-2 text-sm font-medium transition-all uppercase tracking-wider cursor-pointer ${activeTab === 'devices' ? 'bg-white text-black font-bold shadow-md' : 'text-zinc-400 hover:text-white'}`}
            >
              Device Inventory
            </button>
            <button 
              onClick={() => setActiveTab('recovery')}
              className={`px-4 py-2 text-sm font-medium transition-all uppercase tracking-wider cursor-pointer ${activeTab === 'recovery' ? 'bg-white text-black font-bold shadow-md' : 'text-zinc-400 hover:text-white'}`}
            >
              Forensic Recovery
            </button>
          </div>

          <button 
            onClick={() => setView('landing')}
            className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 text-xs font-semibold px-3.5 py-2.5 border border-zinc-700 transition-colors uppercase tracking-wider cursor-pointer"
          >
            Back to Home
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 flex flex-col gap-8">
        
        {/* TAB 1: OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="space-y-8 animate-fadeIn">
            
            {/* KPI Metric Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-zinc-950 border border-zinc-800 p-5 flex items-center justify-between shadow-xl">
                <div>
                  <p className="text-xs font-mono uppercase tracking-wider text-zinc-400">Total Registered Devices</p>
                  <h3 className="text-3xl font-black text-white mt-1">{devices.length} Units</h3>
                  <span className="text-xs font-mono text-zinc-400 mt-2 inline-block">
                    {devices.filter(d => d.type.includes('HDD')).length} HDD, {devices.filter(d => d.type.includes('NVMe') || d.type.includes('SSD') || d.type.includes('SED')).length} SSD/NVMe, {devices.filter(d => d.type.includes('USB') || d.type.includes('External')).length} USB/Ext
                  </span>
                </div>
                <div className="p-3 bg-zinc-900 border border-zinc-700 text-white">
                  <HardDrive className="w-6 h-6" />
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-800 p-5 flex items-center justify-between shadow-xl">
                <div>
                  <p className="text-xs font-mono uppercase tracking-wider text-zinc-400">Successful Sanitizations</p>
                  <h3 className="text-3xl font-black text-white mt-1">{jobs.filter(j => j.status === 'COMPLETE').length} Jobs</h3>
                  <span className="text-xs font-mono text-zinc-300 mt-2 inline-block">Crypto Erase & Block Erase</span>
                </div>
                <div className="p-3 bg-zinc-900 border border-zinc-700 text-white">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-800 p-5 flex items-center justify-between shadow-xl">
                <div>
                  <p className="text-xs font-mono uppercase tracking-wider text-zinc-400">Verification Failures</p>
                  <h3 className="text-3xl font-black text-zinc-300 mt-1">{jobs.filter(j => j.status === 'FAILED_VERIFICATION').length} Incident(s)</h3>
                  <span className="text-xs font-mono text-zinc-400 mt-2 inline-block">Low Entropy Detected</span>
                </div>
                <div className="p-3 bg-zinc-900 border border-zinc-700 text-zinc-300">
                  <XCircle className="w-6 h-6" />
                </div>
              </div>

              <div className="bg-zinc-950 border border-zinc-800 p-5 flex items-center justify-between shadow-xl">
                <div>
                  <p className="text-xs font-mono uppercase tracking-wider text-zinc-400">Pending Operations</p>
                  <h3 className="text-3xl font-black text-zinc-400 mt-1">{jobs.filter(j => j.status === 'QUEUED').length} Queued</h3>
                  <span className="text-xs font-mono text-zinc-400 mt-2 inline-block">Awaiting dispatch</span>
                </div>
                <div className="p-3 bg-zinc-900 border border-zinc-700 text-zinc-400">
                  <Clock className="w-6 h-6" />
                </div>
              </div>
            </div>

            {/* Executive Summary & Highlights */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              <div className="lg:col-span-2 bg-zinc-950 border border-zinc-800 p-6 shadow-xl flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-3 mb-4">
                    <Server className="w-5 h-5 text-white" />
                    <h2 className="text-lg font-bold text-white uppercase tracking-wider">Executive Compliance Summary</h2>
                  </div>
                  <p className="text-zinc-300 text-sm leading-relaxed mb-4">
                    This evaluation tracks six distinct storage devices (<code className="text-white bg-zinc-900 px-1.5 py-0.5 border border-zinc-700">DEV-001</code> through <code className="text-white bg-zinc-900 px-1.5 py-0.5 border border-zinc-700">DEV-006</code>), corresponding erasure jobs, verification results, and issued compliance certificates over secure wire stacks. 
                  </p>
                  <div className="bg-black border border-zinc-800 p-4 space-y-3">
                    <h4 className="text-xs font-mono uppercase tracking-widest text-white">Key Audit Takeaways:</h4>
                    <ul className="space-y-2 text-sm text-zinc-300">
                      <li className="flex items-start gap-2">
                        <span className="text-white font-bold">•</span>
                        <span><strong>Cryptographic Destruction:</strong> SED Opal 2.0 and NVMe drives (<code className="text-white">DEV-002</code>, <code className="text-white">DEV-004</code>) utilized instant key destruction protocols with zero residual data risk.</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-zinc-400 font-bold">•</span>
                        <span><strong>Failed USB Sanitization:</strong> <code className="text-zinc-300">DEV-005</code> failed DoD 5220.22-M verification due to low entropy sampling; certificate withheld under event <code className="text-zinc-300">EVT-1008</code>.</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-zinc-400 font-bold">•</span>
                        <span><strong>Pending Work:</strong> Job <code className="text-zinc-300">ZT-043</code> for <code className="text-zinc-300">DEV-001</code> is queued and ready for technician dispatch.</span>
                      </li>
                    </ul>
                  </div>
                </div>
                <div className="mt-6 flex gap-4">
                  <button 
                    onClick={() => setActiveTab('jobs')}
                    className="flex-1 bg-white hover:bg-zinc-200 text-black font-bold py-3 px-4 shadow-lg transition-all flex items-center justify-center gap-2 uppercase tracking-wider text-xs cursor-pointer"
                  >
                    <Search className="w-4 h-4" />
                    Inspect All Erasure Jobs
                  </button>
                </div>
              </div>

              {/* Quick Actions / Recommendations */}
              <div className="bg-zinc-950 border border-zinc-800 p-6 shadow-xl flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-3 mb-4">
                    <AlertTriangle className="w-5 h-5 text-white" />
                    <h2 className="text-lg font-bold text-white uppercase tracking-wider">Corrective Actions</h2>
                  </div>
                  <div className="space-y-4">
                    <div className="p-3.5 bg-black border border-zinc-700">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono font-bold text-white uppercase">Quarantine DEV-005</span>
                        <span className="text-xs font-mono bg-zinc-900 px-2 py-0.5 text-zinc-300 border border-zinc-800">High Priority</span>
                      </div>
                      <p className="text-xs text-zinc-400">Failed USB drive requires physical shredding or degaussing due to wear-leveling data retention.</p>
                      <button 
                        onClick={() => handleQuarantineDevice('DEV-005')}
                        className="mt-3 w-full bg-white hover:bg-zinc-200 text-black text-xs font-bold py-2 transition-colors uppercase tracking-wider cursor-pointer"
                      >
                        Confirm Physical Shredding
                      </button>
                    </div>

                    <div className="p-3.5 bg-black border border-zinc-800">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono font-bold text-zinc-300 uppercase">Dispatch ZT-043</span>
                        <span className="text-xs font-mono bg-zinc-900 px-2 py-0.5 text-zinc-400 border border-zinc-800">Queued</span>
                      </div>
                      <p className="text-xs text-zinc-400">Initiate NIST 800-88 Purge for WD Blue 1TB HDD (<code className="text-zinc-200">DEV-001</code>).</p>
                      <button 
                        onClick={() => openWipeConfirmation(jobs.find(j => j.jobId === 'ZT-043') || { jobId: 'ZT-043', deviceId: 'DEV-001', method: 'NIST 800-88 Purge - 3-pass', technician: 'TECH-03' })}
                        className="mt-3 w-full bg-zinc-900 hover:bg-zinc-800 text-white font-bold text-xs py-2 border border-zinc-700 transition-colors uppercase tracking-wider cursor-pointer"
                      >
                        Dispatch Job ZT-043
                      </button>
                    </div>
                  </div>
                </div>
              </div>

            </div>

          </div>
        )}

        {/* TAB 2: JOBS & VERIFICATION */}
        {activeTab === 'jobs' && (
          <div className="space-y-6 animate-fadeIn">
            
            <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-zinc-950 p-4 border border-zinc-800">
              <div className="relative w-full md:w-80">
                <Search className="w-4 h-4 text-zinc-400 absolute left-3.5 top-3.5" />
                <input 
                  type="text"
                  placeholder="Search job ID, device, method..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-black border border-zinc-700 rounded-none pl-10 pr-4 py-2.5 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-white"
                />
              </div>

              <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto">
                {['ALL', 'COMPLETE', 'FAILED_VERIFICATION', 'QUEUED'].map((status) => (
                  <button
                    key={status}
                    onClick={() => setFilterStatus(status)}
                    className={`px-3 py-2 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition-all border cursor-pointer ${filterStatus === status ? 'bg-white text-black font-bold border-white' : 'bg-black text-zinc-300 border-zinc-800 hover:border-zinc-600'}`}
                  >
                    {status.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 overflow-hidden shadow-2xl">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-zinc-800 bg-black text-xs font-mono uppercase tracking-wider text-zinc-400">
                      <th className="p-4">Job ID</th>
                      <th className="p-4">Target Device</th>
                      <th className="p-4">Sanitization Standard</th>
                      <th className="p-4">Status</th>
                      <th className="p-4">Technician</th>
                      <th className="p-4">Certificate / Entropy</th>
                      <th className="p-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900 text-sm">
                    {filteredJobs.map((job) => (
                      <tr key={job.jobId} className="hover:bg-zinc-900/40 transition-colors">
                        <td className="p-4 font-mono font-bold text-white">{job.jobId}</td>
                        <td className="p-4 font-semibold text-zinc-200">{job.deviceId}</td>
                        <td className="p-4 text-zinc-300">{job.method}</td>
                        <td className="p-4">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono uppercase ${
                            job.status === 'COMPLETE' ? 'bg-zinc-900 text-white border border-zinc-700' :
                            job.status === 'FAILED_VERIFICATION' ? 'bg-zinc-900 text-zinc-300 border border-zinc-700' :
                            'bg-zinc-900 text-zinc-400 border border-zinc-800'
                          }`}>
                            {job.status === 'COMPLETE' && <CheckCircle2 className="w-3.5 h-3.5 text-white" />}
                            {job.status === 'FAILED_VERIFICATION' && <XCircle className="w-3.5 h-3.5 text-zinc-400" />}
                            {job.status === 'QUEUED' && <Clock className="w-3.5 h-3.5 text-zinc-400" />}
                            {job.status.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="p-4 text-zinc-400 font-mono text-xs">{job.technician}</td>
                        <td className="p-4 text-xs font-mono text-zinc-300">
                          <div>{job.cert}</div>
                          <div className="text-zinc-500">{job.entropy}</div>
                        </td>
                        <td className="p-4 text-right">
                          {job.status === 'QUEUED' ? (
                            <button 
                              onClick={() => openWipeConfirmation(job)}
                              className="bg-white hover:bg-zinc-200 text-black font-bold px-3 py-1.5 text-xs transition-colors flex items-center gap-1 ml-auto uppercase tracking-wider cursor-pointer"
                            >
                              <Lock className="w-3 h-3" /> Run Wipe
                            </button>
                          ) : job.status === 'COMPLETE' ? (
                            <button 
                              onClick={() => setSelectedCert(job)}
                              className="bg-zinc-900 hover:bg-zinc-800 text-white px-3 py-1.5 text-xs font-semibold border border-zinc-700 transition-colors flex items-center gap-1 ml-auto uppercase tracking-wider cursor-pointer"
                            >
                              <FileText className="w-3 h-3" /> View Cert
                            </button>
                          ) : (
                            <span className="text-xs font-mono text-zinc-400 italic">Quarantine Req.</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* TAB 3: DEVICE INVENTORY */}
        {activeTab === 'devices' && (
          <div className="space-y-6 animate-fadeIn">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {devices.map((dev) => (
                <div key={dev.id} className="bg-zinc-950 border border-zinc-800 p-6 shadow-xl flex flex-col justify-between hover:border-white transition-all">
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <span className="font-mono text-white font-bold text-sm bg-zinc-900 px-2.5 py-1 border border-zinc-700">{dev.id}</span>
                      <span className={`text-xs font-mono uppercase px-2.5 py-1 border ${
                        dev.status === 'COMPLETE' ? 'bg-zinc-900 text-white border-zinc-700' :
                        dev.status === 'FAILED_VERIFICATION' ? 'bg-zinc-900 text-zinc-300 border-zinc-700' :
                        dev.status === 'QUARANTINED' ? 'bg-zinc-900 text-zinc-400 border-zinc-700' :
                        'bg-zinc-900 text-zinc-400 border-zinc-800'
                      }`}>
                        {dev.status}
                      </span>
                    </div>

                    <h3 className="text-lg font-bold text-white mb-1 uppercase tracking-wider">{dev.name}</h3>
                    <div className="space-y-1.5 text-xs text-zinc-400 mb-6 font-mono">
                      <div className="flex justify-between"><span>Media Type:</span> <strong className="text-white">{dev.type}</strong></div>
                      <div className="flex justify-between"><span>Capacity:</span> <strong className="text-white">{dev.capacity}</strong></div>
                      <div className="flex justify-between"><span>Assigned Job:</span> <strong className="text-white">{dev.currentJob}</strong></div>
                      <div className="flex justify-between"><span>Technician:</span> <strong className="text-white">{dev.tech}</strong></div>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-zinc-900 flex items-center justify-between">
                    <span className="text-xs font-mono text-zinc-500 uppercase tracking-widest">Tamper-Evident Ledger</span>
                    {dev.status === 'FAILED_VERIFICATION' ? (
                      <button 
                        onClick={() => handleQuarantineDevice(dev.id)}
                        className="bg-white hover:bg-zinc-200 text-black text-xs font-bold px-3 py-1.5 transition-colors uppercase tracking-wider cursor-pointer"
                      >
                        Quarantine
                      </button>
                    ) : (
                      <span className="text-xs font-mono text-white font-semibold flex items-center gap-1 uppercase">
                        <ShieldCheck className="w-3.5 h-3.5" /> Secure
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 4: FORENSIC RECOVERY */}
        {activeTab === 'recovery' && (
          <div className="space-y-6 animate-fadeIn">
            <div className="bg-zinc-950 border border-zinc-800 p-6 shadow-xl">
              <h2 className="text-xl font-bold text-white mb-4 uppercase tracking-wider">Start Recovery Scan</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-xs font-mono text-zinc-400 mb-2 uppercase">Target Storage Drive</label>
                  <select id="recovery-drive-select" className="w-full bg-black border border-zinc-700 text-white text-sm p-3 focus:outline-none focus:border-white">
                    {devices.map(d => (
                      <option key={d.id} value={d.id}>{d.name} ({d.id})</option>
                    ))}
                  </select>
                </div>
                <div className="flex flex-col justify-end gap-3">
                  <div className="flex items-center gap-4">
                    <label className="flex items-center gap-2 text-xs text-zinc-300 font-mono cursor-pointer">
                      <input type="checkbox" id="recovery-demo-mode" defaultChecked className="accent-white w-4 h-4" /> Demo Mode
                    </label>
                    <label className="flex items-center gap-2 text-xs text-zinc-300 font-mono cursor-pointer">
                      <input type="checkbox" id="recovery-post-erasure" className="accent-white w-4 h-4" /> Post-Erasure Scan
                    </label>
                  </div>
                  <button 
                    onClick={() => {
                      const sel = document.getElementById('recovery-drive-select').value;
                      const isDemo = document.getElementById('recovery-demo-mode').checked;
                      const isPost = document.getElementById('recovery-post-erasure').checked;
                      const devObj = devices.find(d => d.id === sel) || {};
                      openRecoveryConfirmation(sel, devObj.name || sel, async () => {
                        triggerToast('Starting recovery scan on ' + sel + '...');
                        try {
                          const res = await fetch('/api/recovery/confirm', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ device_path: sel, demo_mode: isDemo, post_erasure: isPost, operator_id: 'ZT-OPERATOR-01' })
                          });
                          const data = await res.json();
                          setRecoveryResults(data);
                          triggerToast('Recovery scan complete! Case: ' + data.case_id);
                          
                          setJobs(prev => [{
                            jobId: 'REC-JOB-' + Math.floor(1000 + Math.random() * 9000),
                            deviceId: sel,
                            method: 'Forensic Recovery' + (isPost ? ' (Post-Erasure)' : ''),
                            status: 'COMPLETE',
                            technician: 'SYSTEM',
                            cert: 'N/A (Read-Only)',
                            entropy: 'Found ' + data.files_recovered.length + ' artifact(s)'
                          }, ...prev]);
                          
                        } catch (e) {
                          triggerToast('Error: ' + e.message);
                        }
                      });
                    }}
                    className="w-full bg-white hover:bg-zinc-200 text-black font-bold py-3 transition-colors uppercase tracking-wider cursor-pointer"
                  >
                    Start Scan
                  </button>
                </div>
              </div>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 shadow-xl overflow-hidden">
              <div className="p-4 border-b border-zinc-800 flex justify-between items-center">
                 <h2 className="text-sm font-bold text-white uppercase tracking-wider">Recovery Results</h2>
                 {typeof recoveryResults !== 'undefined' && recoveryResults && (
                   <span className="text-xs font-mono text-zinc-400">Case ID: <strong className="text-white">{recoveryResults.case_id}</strong></span>
                 )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-black text-xs font-mono uppercase tracking-wider text-zinc-400 border-b border-zinc-800">
                      <th className="p-4">Filename</th>
                      <th className="p-4">Type</th>
                      <th className="p-4">Confidence</th>
                      <th className="p-4 text-right">Fragmented</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-900 text-sm">
                    {typeof recoveryResults !== 'undefined' && recoveryResults ? (
                      recoveryResults.files_recovered.map((f, i) => (
                        <tr key={i} className="hover:bg-zinc-900/40 transition-colors">
                          <td className="p-4 font-mono font-bold text-white">{f.filename}</td>
                          <td className="p-4 text-zinc-300">{f.type}</td>
                          <td className="p-4 text-xs font-mono text-zinc-400">{f.confidence}</td>
                          <td className="p-4 text-right">
                            {f.fragmented ? <span className="text-zinc-500">Yes</span> : <span className="text-zinc-300">No</span>}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="4" className="p-8 text-center text-xs font-mono text-zinc-600 uppercase tracking-widest">No recovery data</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

      </main>

      {/* Certificate Modal */}
      {selectedCert && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-zinc-950 border border-zinc-700 max-w-lg w-full p-6 shadow-2xl relative">
            <button 
              onClick={() => setSelectedCert(null)}
              className="absolute top-4 right-4 text-zinc-400 hover:text-white font-bold text-lg cursor-pointer"
            >
              ✕
            </button>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-zinc-900 text-white border border-zinc-700">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white uppercase tracking-wider">Cryptographic Certificate</h3>
                <p className="text-xs font-mono text-zinc-400">{selectedCert.cert}</p>
              </div>
            </div>

            <div className="space-y-3 bg-black p-4 border border-zinc-800 text-xs font-mono text-zinc-300">
              <div className="flex justify-between"><span>Job ID:</span> <strong className="text-white">{selectedCert.jobId}</strong></div>
              <div className="flex justify-between"><span>Target Device:</span> <strong className="text-white">{selectedCert.deviceId}</strong></div>
              <div className="flex justify-between"><span>Sanitization Standard:</span> <strong className="text-white">{selectedCert.method}</strong></div>
              <div className="flex justify-between"><span>Assigned Technician:</span> <strong className="text-white">{selectedCert.technician}</strong></div>
              <div className="flex justify-between"><span>Entropy & Verification:</span> <strong className="text-white">{selectedCert.entropy}</strong></div>
              <div className="flex justify-between"><span>Digital Signature:</span> <strong className="text-white">Valid (SHA-256 Authenticated)</strong></div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button 
                onClick={() => {
                  triggerToast(`Certificate ${selectedCert.cert} downloaded successfully.`);
                  setSelectedCert(null);
                }}
                className="bg-white hover:bg-zinc-200 text-black font-bold px-4 py-2 text-xs transition-colors uppercase tracking-wider cursor-pointer"
              >
                Download PDF Certificate
              </button>
              <button 
                onClick={() => setSelectedCert(null)}
                className="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 px-4 py-2 text-xs font-semibold border border-zinc-700 transition-colors uppercase tracking-wider cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* WIPE CONFIRMATION MODAL — 3-Step Destructive Action Gate          */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {wipeConfirmModal && (
        <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-zinc-950 border border-red-900/60 max-w-lg w-full p-6 shadow-2xl relative">
            <button 
              onClick={closeWipeConfirmation}
              className="absolute top-4 right-4 text-zinc-400 hover:text-white font-bold text-lg cursor-pointer"
            >
              ✕
            </button>

            {/* Header */}
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 bg-red-950 text-red-400 border border-red-900">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white uppercase tracking-wider">Destructive Operation</h3>
                <p className="text-xs font-mono text-red-400">All data will be permanently erased</p>
              </div>
            </div>

            {/* Device Details — always visible */}
            <div className="bg-black border border-zinc-800 p-4 mb-5 space-y-2 text-xs font-mono text-zinc-300">
              <div className="flex justify-between"><span className="text-zinc-500">Device:</span> <strong className="text-white">{wipeConfirmModal.deviceName}</strong></div>
              <div className="flex justify-between"><span className="text-zinc-500">Device ID:</span> <strong className="text-white">{wipeConfirmModal.deviceId}</strong></div>
              <div className="flex justify-between"><span className="text-zinc-500">Media Type:</span> <strong className="text-white">{wipeConfirmModal.type}</strong></div>
              <div className="flex justify-between"><span className="text-zinc-500">Capacity:</span> <strong className="text-white">{wipeConfirmModal.capacity}</strong></div>
              <div className="flex justify-between"><span className="text-zinc-500">Method:</span> <strong className="text-red-300">{wipeConfirmModal.method}</strong></div>
              <div className="flex justify-between"><span className="text-zinc-500">Technician:</span> <strong className="text-white">{wipeConfirmModal.tech}</strong></div>
            </div>

            {/* Step 1: Typed Confirmation */}
            {wipeConfirmStep === 1 && (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-zinc-400 mb-2 uppercase">
                    Step 1 of 2 — Type <span className="text-red-400 font-bold">WIPE {wipeConfirmModal.deviceId}</span> to confirm
                  </label>
                  <input
                    type="text"
                    value={wipeTypedText}
                    onChange={(e) => setWipeTypedText(e.target.value)}
                    placeholder={`WIPE ${wipeConfirmModal.deviceId}`}
                    className="w-full bg-black border border-zinc-700 text-white text-sm font-mono p-3 focus:outline-none focus:border-red-600"
                    autoFocus
                  />
                  {wipeTypedText.length > 0 && wipeTypedText !== `WIPE ${wipeConfirmModal.deviceId}` && (
                    <p className="text-xs text-red-500 mt-1 font-mono">Text does not match. Type exactly as shown above.</p>
                  )}
                </div>
                <div className="flex justify-end gap-3">
                  <button onClick={closeWipeConfirmation} className="px-4 py-2 bg-zinc-900 text-zinc-300 text-xs border border-zinc-700 cursor-pointer uppercase tracking-wider">Cancel</button>
                  <button
                    onClick={() => setWipeConfirmStep(2)}
                    disabled={wipeTypedText !== `WIPE ${wipeConfirmModal.deviceId}`}
                    className={`px-5 py-2 text-xs font-bold uppercase tracking-wider cursor-pointer transition-all ${
                      wipeTypedText === `WIPE ${wipeConfirmModal.deviceId}`
                        ? 'bg-red-600 hover:bg-red-500 text-white'
                        : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
                    }`}
                  >
                    Next — Enter Security PIN
                  </button>
                </div>
              </div>
            )}

            {/* Step 2: Fallback 2FA PIN */}
            {wipeConfirmStep === 2 && (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-zinc-400 mb-2 uppercase">
                    Step 2 of 2 — Security PIN <span className="text-zinc-600">(Fallback 2FA)</span>
                  </label>
                  <div className="relative">
                    <KeyRound className="w-4 h-4 text-zinc-500 absolute left-3 top-3.5" />
                    <input
                      type="password"
                      value={wipePin}
                      onChange={(e) => { setWipePin(e.target.value); setWipeError(''); }}
                      placeholder="Enter your technician PIN"
                      className="w-full bg-black border border-zinc-700 text-white text-sm font-mono p-3 pl-10 focus:outline-none focus:border-red-600"
                      autoFocus
                    />
                  </div>
                </div>
                {wipeError && (
                  <div className="p-3 bg-red-950/50 border border-red-900 text-xs text-red-300 font-mono">
                    <XCircle className="w-3.5 h-3.5 inline mr-1.5" />{wipeError}
                  </div>
                )}
                <div className="flex justify-end gap-3">
                  <button onClick={() => { setWipeConfirmStep(1); setWipeError(''); }} className="px-4 py-2 bg-zinc-900 text-zinc-300 text-xs border border-zinc-700 cursor-pointer uppercase tracking-wider">Back</button>
                  <button
                    onClick={handleConfirmedWipe}
                    disabled={wipePin.length === 0}
                    className={`px-5 py-2 text-xs font-bold uppercase tracking-wider cursor-pointer transition-all ${
                      wipePin.length > 0
                        ? 'bg-red-600 hover:bg-red-500 text-white'
                        : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
                    }`}
                  >
                    Confirm & Start Wipe
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* RECOVERY CONFIRMATION MODAL — Lightweight Read-Only Notice        */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {recoveryConfirmModal && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-zinc-950 border border-zinc-700 max-w-md w-full p-6 shadow-2xl relative">
            <button 
              onClick={closeRecoveryConfirmation}
              className="absolute top-4 right-4 text-zinc-400 hover:text-white font-bold text-lg cursor-pointer"
            >
              ✕
            </button>

            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 bg-zinc-900 text-white border border-zinc-700">
                <Search className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white uppercase tracking-wider">Confirm Recovery Scan</h3>
                <p className="text-xs font-mono text-zinc-400">Read-only forensic operation</p>
              </div>
            </div>

            <div className="bg-black border border-zinc-800 p-4 mb-4 space-y-2 text-xs font-mono text-zinc-300">
              <div className="flex justify-between"><span className="text-zinc-500">Target:</span> <strong className="text-white">{recoveryConfirmModal.deviceName} ({recoveryConfirmModal.deviceId})</strong></div>
            </div>

            <div className="p-3 bg-zinc-900 border border-zinc-800 mb-5 text-xs text-zinc-300">
              <ShieldCheck className="w-3.5 h-3.5 inline mr-1.5 text-white" />
              This operation is <strong className="text-white">READ-ONLY</strong> and will not modify, erase, or write to the source device. Recovery actions are audit-logged.
            </div>

            <div className="flex justify-end gap-3">
              <button onClick={closeRecoveryConfirmation} className="px-4 py-2 bg-zinc-900 text-zinc-300 text-xs border border-zinc-700 cursor-pointer uppercase tracking-wider">Cancel</button>
              <button
                onClick={async () => {
                  closeRecoveryConfirmation();
                  if (pendingRecoveryAction) await pendingRecoveryAction();
                }}
                className="px-5 py-2 bg-white hover:bg-zinc-200 text-black font-bold text-xs uppercase tracking-wider cursor-pointer"
              >
                Confirm & Start Recovery
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-zinc-800 bg-black py-6 text-center text-xs text-zinc-500 font-mono uppercase tracking-widest">
        Data Erasure & Compliance Audit Dashboard • Built with React & Tailwind CSS • August 24, 2026
      </footer>

    </div>
  );
}