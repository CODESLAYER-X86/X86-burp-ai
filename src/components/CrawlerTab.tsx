import React, { useState } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { Network, Search, Filter } from 'lucide-react';

interface CrawlerTabProps {
  engine: SecurityEngineService;
}

export const CrawlerTab: React.FC<CrawlerTabProps> = ({ engine }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'parameterized'>('all');

  const filteredEndpoints = engine.endpoints.filter((ep) => {
    const matchesSearch = ep.path.toLowerCase().includes(searchTerm.toLowerCase()) || ep.method.includes(searchTerm.toUpperCase());
    if (filterType === 'parameterized') {
      return matchesSearch && ep.parameters.length > 0;
    }
    return matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-white font-semibold text-base mb-1">
              <Network className="h-4 w-4 text-red-400" />
              <span>Queue-Based Site Crawler & Attack Surface Mapping</span>
            </div>
            <p className="text-xs text-neutral-400">
              Autonomous link discovery, deduplication, and form parameter inventory. Output is compacted into high-density summaries for Gemma 4 31B.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-neutral-400">
              {engine.endpoints.length} Endpoints Discovered
            </span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-neutral-400" />
          <input
            type="text"
            placeholder="Search path or method..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-neutral-950 border border-neutral-800 rounded pl-9 pr-3 py-1.5 text-xs text-white placeholder-neutral-400 focus:outline-none focus:border-red-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-1 bg-neutral-900 p-1 rounded border border-neutral-800 self-stretch sm:self-auto">
          <button
            onClick={() => setFilterType('all')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
              filterType === 'all'
                ? 'bg-neutral-800 text-white shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            All Endpoints ({engine.endpoints.length})
          </button>
          <button
            onClick={() => setFilterType('parameterized')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
              filterType === 'parameterized'
                ? 'bg-neutral-800 text-white shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            Parameterized Vectors ({engine.endpoints.filter(e => e.parameters.length > 0).length})
          </button>
        </div>
      </div>

      {/* Discovered Endpoints Table */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-neutral-950/80 border-b border-neutral-800 text-neutral-400 uppercase text-[11px]">
              <tr>
                <th className="py-2.5 px-4">Method</th>
                <th className="py-2.5 px-4">Path</th>
                <th className="py-2.5 px-4">Parameters</th>
                <th className="py-2.5 px-4">Source</th>
                <th className="py-2.5 px-4 text-right">Target Host</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/60 text-neutral-300">
              {filteredEndpoints.map((ep, idx) => (
                <tr key={idx} className="hover:bg-neutral-800/30 transition-colors">
                  <td className="py-2.5 px-4">
                    <span
                      className={`font-semibold ${
                        ep.method === 'GET'
                          ? 'text-sky-400'
                          : ep.method === 'POST'
                          ? 'text-emerald-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {ep.method}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-white font-medium">
                    {ep.path}
                  </td>
                  <td className="py-2.5 px-4">
                    {ep.parameters.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {ep.parameters.map((p, pIdx) => (
                          <span
                            key={pIdx}
                            className="bg-neutral-950 border border-neutral-800 px-1.5 py-0.5 rounded text-neutral-300 text-[11px]"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-neutral-400 text-xs">None</span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-neutral-400">
                    {ep.source}
                  </td>
                  <td className="py-2.5 px-4 text-right text-neutral-400">
                    {ep.host}:{ep.port}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
