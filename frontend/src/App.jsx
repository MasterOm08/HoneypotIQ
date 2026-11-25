import { useState } from 'react';
import './App.css';

const API_BASE = 'http://localhost:8081/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('detection'); // 'detection' | 'benchmark'
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Detection parameters
  const [simSize, setSimSize] = useState(10000);
  const [topK, setTopK] = useState(5);
  const [ttlMs, setTtlMs] = useState(15000);
  const [csvFile, setCsvFile] = useState(null);
  const [startBucket, setStartBucket] = useState('');
  const [endBucket, setEndBucket] = useState('');

  // Outputs
  const [analysis, setAnalysis] = useState(null);
  const [benchmarks, setBenchmarks] = useState(null);

  const runSimulation = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/simulate?size=${simSize}&topK=${topK}&ttlMs=${ttlMs}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Simulation failed');
      setAnalysis(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCsvUpload = async (e) => {
    e.preventDefault();
    if (!csvFile) {
      setError('Please select a CSV file (e.g., sample_10k.csv) first.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const formData = new FormData();
      formData.append('file', csvFile);
      formData.append('topK', topK);
      formData.append('ttlMs', ttlMs);
      if (startBucket !== '') formData.append('startBucket', startBucket);
      if (endBucket !== '') formData.append('endBucket', endBucket);

      const res = await fetch(`${API_BASE}/analyze/csv`, {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'CSV analysis failed');
      setAnalysis(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runBenchmarks = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/benchmark`);
      const data = await res.json();
      if (!res.ok) throw new Error('Benchmark failed');
      setBenchmarks(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <header className="header">
        <div>
          <h1>HoneypotIQ</h1>
          <p className="subtitle">
            Adaptive Port-Scan &amp; Reconnaissance Detection Engine (Trie • Red-Black Tree • Segment Tree • Randomized Quickselect)
          </p>
        </div>
        <div className="tabs">
          <button
            className={activeTab === 'detection' ? 'tab active' : 'tab'}
            onClick={() => setActiveTab('detection')}
          >
            SOC Threat Detection
          </button>
          <button
            className={activeTab === 'benchmark' ? 'tab active' : 'tab'}
            onClick={() => setActiveTab('benchmark')}
          >
            Empirical Benchmarks
          </button>
        </div>
      </header>

      {error && <div className="error-banner">{error}</div>}

      {activeTab === 'detection' && (
        <div className="panel">
          <div className="controls-grid">
            {/* Synthetic Simulation Card */}
            <div className="card">
              <h3>1. Quick Synthetic Stream Simulation</h3>
              <div className="form-row">
                <label>Event Stream Size (N):</label>
                <select value={simSize} onChange={(e) => setSimSize(Number(e.target.value))}>
                  <option value={1000}>1,000 events</option>
                  <option value={10000}>10,000 events</option>
                  <option value={50000}>50,000 events</option>
                  <option value={100000}>100,000 events</option>
                </select>
              </div>
              <div className="form-row">
                <label>Top-K Scanners (Quickselect):</label>
                <input type="number" min="1" max="50" value={topK} onChange={(e) => setTopK(Number(e.target.value))} />
              </div>
              <div className="form-row">
                <label>Session TTL (ms) (Red-Black Tree):</label>
                <input type="number" min="1000" step="1000" value={ttlMs} onChange={(e) => setTtlMs(Number(e.target.value))} />
              </div>
              <button className="btn-primary" onClick={runSimulation} disabled={loading}>
                {loading ? 'Processing...' : 'Run Live Stream Detection'}
              </button>
            </div>

            {/* CSV Upload Card */}
            <form className="card" onSubmit={handleCsvUpload}>
              <h3>2. Upload Connection Metadata CSV</h3>
              <div className="form-row">
                <label>Log Dataset (.csv):</label>
                <input type="file" accept=".csv" onChange={(e) => setCsvFile(e.target.files[0])} />
              </div>
              <div className="form-row split">
                <div>
                  <label>Start Bucket [L]:</label>
                  <input
                    type="number"
                    placeholder="0"
                    value={startBucket}
                    onChange={(e) => setStartBucket(e.target.value)}
                  />
                </div>
                <div>
                  <label>End Bucket [R]:</label>
                  <input
                    type="number"
                    placeholder="Max"
                    value={endBucket}
                    onChange={(e) => setEndBucket(e.target.value)}
                  />
                </div>
              </div>
              <button className="btn-secondary" type="submit" disabled={loading}>
                {loading ? 'Analyzing CSV...' : 'Analyze Uploaded Log'}
              </button>
            </form>
          </div>

          {analysis && (
            <div className="results-section">
              <div className="metrics-row">
                <div className="metric-box">
                  <span className="metric-label">Events Processed</span>
                  <span className="metric-value">{analysis.totalEventsProcessed.toLocaleString()}</span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Active / Evicted (RB-Tree)</span>
                  <span className="metric-value">
                    {analysis.activeSessionsRetained.toLocaleString()} / {analysis.expiredSessionsEvicted.toLocaleString()}
                  </span>
                </div>
                <div className="metric-box">
                  <span className="metric-label">Window Intensity / Peak (SegTree)</span>
                  <span className="metric-value">
                    {analysis.windowTotalIntensity.toLocaleString()} / {analysis.windowPeakBucketIntensity.toLocaleString()}
                  </span>
                </div>
                <div className="metric-box highlight">
                  <span className="metric-label">Engine Latency</span>
                  <span className="metric-value">{(analysis.executionTimeMicros / 1000).toFixed(2)} ms</span>
                </div>
              </div>

              <h3>Top-{analysis.topSuspiciousSources.length} High-Risk Reconnaissance Sources (Randomized Quickselect — CO5)</h3>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Source IP</th>
                    <th>Trie Policy Match</th>
                    <th>Unique Ports Probed</th>
                    <th>Unique Hosts Probed</th>
                    <th>Honeypot Decoy Hits</th>
                    <th>Total Events</th>
                    <th>Composite Risk Score</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.topSuspiciousSources.map((src, idx) => (
                    <tr key={src.srcIp} className={src.honeypotHits > 0 ? 'row-critical' : ''}>
                      <td>#{idx + 1}</td>
                      <td className="mono">{src.srcIp}</td>
                      <td><span className="badge">{src.policyAction}</span></td>
                      <td>{src.uniquePortsProbed}</td>
                      <td>{src.uniqueHostsProbed}</td>
                      <td><strong>{src.honeypotHits}</strong></td>
                      <td>{src.totalEvents}</td>
                      <td><strong>{src.riskScore.toFixed(1)}</strong></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'benchmark' && (
        <div className="panel">
          <div className="card">
            <h3>Scaled Performance &amp; Memory Benchmark (HoneypotIQ vs. Naive HashMap Baseline)</h3>
            <p>
              Compares custom Bitwise Prefix Trie + Red-Black Tree + Segment Tree + Randomized Quickselect against a
              conventional per-source HashMap detector with linear window scans and O(N log N) sorting across N = 1k, 10k, and 100k events.
            </p>
            <button className="btn-primary" onClick={runBenchmarks} disabled={loading}>
              {loading ? 'Running Scaled Experiments...' : 'Run 1k / 10k / 100k Benchmark Suite'}
            </button>
          </div>

          {benchmarks && (
            <div className="results-section">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Dataset Size (N)</th>
                    <th>HoneypotIQ Time</th>
                    <th>Naive Baseline Time</th>
                    <th>Speedup Factor</th>
                    <th>RB-Tree Retained Sessions</th>
                    <th>Baseline Retained Records</th>
                  </tr>
                </thead>
                <tbody>
                  {benchmarks.map((b) => (
                    <tr key={b.datasetSize}>
                      <td><strong>{b.datasetSize.toLocaleString()} events</strong></td>
                      <td>{(b.honeypotIqTimeMicros / 1000).toFixed(2)} ms</td>
                      <td>{(b.baselineTimeMicros / 1000).toFixed(2)} ms</td>
                      <td className="speedup">{b.speedupFactor}x faster</td>
                      <td>{b.activeSessionsAfterEviction.toLocaleString()}</td>
                      <td>{b.baselineRetainedRecords.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}