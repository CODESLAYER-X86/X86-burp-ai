import React, { useState, useEffect } from 'react';
import { SecurityEngineService } from './services/securityEngine';
import { Header } from './components/Header';
import { OverviewTab } from './components/OverviewTab';
import { ScopeTab } from './components/ScopeTab';
import { CrawlerTab } from './components/CrawlerTab';
import { RepeaterTab } from './components/RepeaterTab';
import { FuzzerTab } from './components/FuzzerTab';
import { FindingsTab } from './components/FindingsTab';
import { QuotaMonitorTab } from './components/QuotaMonitorTab';
import { LabTargetTab } from './components/LabTargetTab';
import { ReportModal } from './components/ReportModal';

export default function App() {
  const [engine] = useState(() => SecurityEngineService.getInstance());
  const [, setTick] = useState(0);
  const [activeTab, setActiveTab] = useState('overview');
  const [showReportModal, setShowReportModal] = useState(false);

  useEffect(() => {
    // Re-render when engine state changes
    const unsubscribe = engine.subscribe(() => {
      setTick((t) => t + 1);
    });
    return unsubscribe;
  }, [engine]);

  return (
    <div className="min-h-screen bg-[#090d16] text-neutral-100 font-sans selection:bg-red-950 selection:text-red-300">
      <Header
        engine={engine}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onExportReport={() => setShowReportModal(true)}
      />

      <main className="max-w-[1440px] mx-auto p-6 md:p-8">
        {activeTab === 'overview' && <OverviewTab engine={engine} />}
        {activeTab === 'scope' && <ScopeTab engine={engine} />}
        {activeTab === 'crawler' && <CrawlerTab engine={engine} />}
        {activeTab === 'repeater' && <RepeaterTab engine={engine} />}
        {activeTab === 'fuzzer' && <FuzzerTab engine={engine} />}
        {activeTab === 'findings' && <FindingsTab engine={engine} />}
        {activeTab === 'quota' && <QuotaMonitorTab engine={engine} />}
        {activeTab === 'lab' && <LabTargetTab engine={engine} />}
      </main>

      {showReportModal && (
        <ReportModal
          engine={engine}
          onClose={() => setShowReportModal(false)}
        />
      )}
    </div>
  );
}
