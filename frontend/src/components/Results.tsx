import React from 'react';
import { AlertCircle } from 'lucide-react';

interface Vulnerability {
  risk: string;
  alert_type: string;
  alert_tags: string;
  parameter?: string;
  evidence?: string;
  description: string;
  solution: string;
}

interface ResultsProps {
  isVisible: boolean;
  vulnerabilities: Vulnerability[];
  stats: {
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
}

const Results: React.FC<ResultsProps> = ({ isVisible, vulnerabilities, stats }) => {
  if (!isVisible) return null;

  return (
    <section className="mt-8">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        {Object.entries(stats).map(([type, count]) => (
          <div key={type} className="bg-gray-800 p-6 rounded-lg shadow-md text-center border border-gray-700">
            <h3 className="text-lg font-semibold mb-2 capitalize text-gray-100">{type} Risk</h3>
            <span className="text-4xl font-bold block mb-2" style={{
              color: type === 'high' ? '#ef4444' :
                     type === 'medium' ? '#f59e0b' :
                     type === 'low' ? '#3b82f6' : '#60a5fa'
            }}>
              {count}
            </span>
            <p className="text-gray-300">
              {type === 'informational' ? 'Information notices' : `${type} vulnerabilities detected`}
            </p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2">
          <h3 className="text-xl font-semibold mb-4 text-gray-100">Vulnerability Findings</h3>
          <div className="space-y-6">
            {vulnerabilities.map((vuln, index) => (
              <div
                key={index}
                className={`bg-gray-800 rounded-lg shadow-md border-l-4 ${
                  vuln.risk.toLowerCase() === 'low'
                    ? 'border-blue-600'
                    : 'border-blue-400'
                }`}
              >
                <div className="p-4 border-b border-gray-700 flex justify-between items-center">
                  <div className="flex items-center gap-3">
                    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                      vuln.risk.toLowerCase() === 'low'
                        ? 'bg-blue-900 text-blue-200'
                        : 'bg-blue-900/50 text-blue-300'
                    }`}>
                      {vuln.risk}
                    </span>
                    <span className="font-mono text-sm bg-gray-700 px-3 py-1 rounded text-gray-200">
                      {vuln.alert_type}
                    </span>
                  </div>
                </div>
                <div className="p-4">
                  <dl className="space-y-4">
                    <div>
                      <dt className="font-semibold text-gray-300">Alert Tags</dt>
                      <dd className="mt-1 text-gray-300">{vuln.alert_tags}</dd>
                    </div>
                    {vuln.parameter && (
                      <div>
                        <dt className="font-semibold text-gray-300">Parameter</dt>
                        <dd className="mt-1 text-gray-300">{vuln.parameter}</dd>
                      </div>
                    )}
                    {vuln.evidence && (
                      <div>
                        <dt className="font-semibold text-gray-300">Evidence</dt>
                        <dd className="mt-1 font-mono text-sm bg-gray-700 p-2 rounded text-gray-200">
                          {vuln.evidence}
                        </dd>
                      </div>
                    )}
                    <div>
                      <dt className="font-semibold text-gray-300">Description</dt>
                      <dd className="mt-1 text-gray-300">{vuln.description}</dd>
                    </div>
                    <div>
                      <dt className="font-semibold text-gray-300">Solution</dt>
                      <dd className="mt-1 text-gray-300">{vuln.solution}</dd>
                    </div>
                  </dl>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gradient-to-br from-blue-800 to-blue-600 rounded-lg p-6 text-white h-fit sticky top-6 border border-blue-500/30">
          <div className="bg-white/20 rounded-full w-12 h-12 flex items-center justify-center mb-4">
            <AlertCircle className="h-6 w-6" />
          </div>
          <h4 className="text-xl font-semibold mb-3">Critical Security Insights Available</h4>
          <p className="mb-6 opacity-90">
            Your scan has identified additional security concerns that require immediate attention.
            Access our comprehensive security report for complete vulnerability analysis.
          </p>
          <button
            onClick={() => {}} // TODO: Implement report request
            className="w-full bg-white/15 hover:bg-white/25 transition-colors rounded-lg py-3 px-4 flex items-center justify-between"
          >
            <span>View Complete Report</span>
            <span>→</span>
          </button>
        </div>
      </div>
    </section>
  );
};

export default Results;