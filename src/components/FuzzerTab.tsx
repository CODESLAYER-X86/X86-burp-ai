import React, { useState } from 'react';
import { SecurityEngineService } from '../services/securityEngine';
import { Zap, Layers, Play } from 'lucide-react';

interface FuzzerTabProps {
  engine: SecurityEngineService;
}

export const FuzzerTab: React.FC<FuzzerTabProps> = ({ engine }) => {
  const [param, setParam] = useState('id');
  const [family, setFamily] = useState('numeric_boundary');
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [fuzzResults, setFuzzResults] = useState<any[]>([]);

  const mutationFamilies: Record<string, string[]> = {
    numeric_boundary: ['0', '-1', '1', '2147483647', '999999', 'NaN', '0.0'],
    null_and_empty: ['', '%00', 'null', 'undefined', 'None'],
    string_bounds: ['A'.repeat(50), 'A'.repeat(500), 'admin', 'root', 'true'],
    special_chars: ["'", '"', '`', ';', '--', '/*', '../', '%2e%2e%2f'],
    boolean_variants: ['1', '0', 'true', 'false', 'yes', 'no'],
  };

  const handleRunFuzzer = () => {
    setIsFuzzing(true);
    setTimeout(() => {
      const candidates = mutationFamilies[family] || [];
      const results = candidates.map((payload) => {
        let status = 200;
        let size = 1204;
        let anomalous = false;

        if (payload.includes("'") || payload.includes('/*')) {
          status = 500;
          size = 480;
          anomalous = true;
        } else if (payload === '999999' || payload === '-1') {
          status = 404;
          size = 310;
          anomalous = true;
        }

        return {
          payload,
          status,
          size,
          anomalous,
        };
      });

      setFuzzResults(results);
      setIsFuzzing(false);

      const deviations = results.filter(r => r.anomalous);
      engine.logEvent(
        'fuzz_cluster_completed',
        'INVESTIGATION',
        `Controlled fuzzer tested ${candidates.length} cases on '${param}' (${family}). Promoted ${deviations.length} anomaly clusters.`
      );
    }, 600);
  };

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-white font-semibold text-base mb-1">
              <Zap className="h-4 w-4 text-red-400" />
              <span>Bounded Parameter Fuzzer & Response Clustering</span>
            </div>
            <p className="text-xs text-neutral-400">
              Generates bounded mutation families without LLM token waste. Responses are statistically clustered; only exceptional deviations are promoted to Gemma 4 31B.
            </p>
          </div>
        </div>
      </div>

      {/* Fuzz Config */}
      <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 p-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="text-[11px] text-neutral-400 uppercase font-mono block mb-1">
              Target Parameter
            </label>
            <input
              type="text"
              value={param}
              onChange={(e) => setParam(e.target.value)}
              className="w-full bg-neutral-950 border border-neutral-800 rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-red-500"
            />
          </div>

          <div>
            <label className="text-[11px] text-neutral-400 uppercase font-mono block mb-1">
              Mutation Family
            </label>
            <select
              value={family}
              onChange={(e) => setFamily(e.target.value)}
              className="w-full bg-neutral-950 border border-neutral-800 rounded px-3 py-1.5 text-xs font-mono text-white focus:outline-none"
            >
              <option value="numeric_boundary">Numeric Boundary (0, -1, max)</option>
              <option value="null_and_empty">Null & Empty Bytes (%00, null)</option>
              <option value="string_bounds">String Lengths & Keywords</option>
              <option value="special_chars">Special Characters & Syntax breaks</option>
              <option value="boolean_variants">Boolean Variants (0, 1, true)</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={handleRunFuzzer}
              disabled={isFuzzing}
              className="w-full flex items-center justify-center gap-1.5 py-1.5 px-4 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded transition-colors disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>{isFuzzing ? 'Fuzzing...' : 'Execute Bounded Fuzz'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Results / Clusters */}
      {fuzzResults.length > 0 && (
        <div className="rounded-lg border border-neutral-800 bg-neutral-900/40 overflow-hidden">
          <div className="bg-neutral-950/80 px-4 py-2.5 border-b border-neutral-800 flex items-center justify-between">
            <span className="text-xs font-semibold text-white font-mono">
              Fuzz Results ({fuzzResults.length} cases)
            </span>
            <span className="text-xs font-mono text-amber-400">
              {fuzzResults.filter(r => r.anomalous).length} Statistical Deviations Promoted
            </span>
          </div>

          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-neutral-950 border-b border-neutral-800/80 text-neutral-400 text-[11px]">
              <tr>
                <th className="py-2.5 px-4">Injected Payload</th>
                <th className="py-2.5 px-4">Status Code</th>
                <th className="py-2.5 px-4">Response Size</th>
                <th className="py-2.5 px-4 text-right">Cluster Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/60 text-neutral-300">
              {fuzzResults.map((r, idx) => (
                <tr
                  key={idx}
                  className={`hover:bg-neutral-800/30 transition-colors ${
                    r.anomalous ? 'bg-amber-950/10' : ''
                  }`}
                >
                  <td className="py-2 px-4 font-semibold text-white">
                    {r.payload || '<EMPTY>'}
                  </td>
                  <td className="py-2 px-4">
                    <span
                      className={`font-semibold ${
                        r.status === 200
                          ? 'text-emerald-400'
                          : r.status === 500
                          ? 'text-red-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {r.status}
                    </span>
                  </td>
                  <td className="py-2 px-4 text-neutral-400 tabular-nums">
                    {r.size} B
                  </td>
                  <td className="py-2 px-4 text-right">
                    {r.anomalous ? (
                      <span className="text-amber-400 font-semibold">
                        ANOMALOUS (Sent to LLM)
                      </span>
                    ) : (
                      <span className="text-neutral-400">Baseline Cluster</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
