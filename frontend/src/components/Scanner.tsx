import React, { useState } from 'react';
import { Loader } from 'lucide-react';

interface ScannerProps {
  onScanSubmit: (url: string) => void;
  isLoading: boolean;
}

const Scanner: React.FC<ScannerProps> = ({ onScanSubmit, isLoading }) => {
  const [url, setUrl] = useState('');
  const [activeType, setActiveType] = useState<'network' | 'application'>('network');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onScanSubmit(url);
  };

  return (
    <section className="max-w-3xl mx-auto mb-16" data-aos="fade-up">
      <div className="flex justify-center gap-4 mb-8">
        <button
          className={`px-6 py-3 rounded-lg transition-colors ${
            activeType === 'network'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
          }`}
          onClick={() => setActiveType('network')}
        >
          Network Scanning
        </button>
        <button
          className={`px-6 py-3 rounded-lg transition-colors ${
            activeType === 'application'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
          }`}
          onClick={() => setActiveType('application')}
        >
          Application Scanning
        </button>
      </div>

      <form onSubmit={handleSubmit} className="bg-gray-800 p-8 rounded-lg shadow-md border border-gray-700">
        <div className="flex gap-4">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter target URL (e.g., example.com)"
            className="flex-1 px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all"
            required
          />
          <button
            type="submit"
            disabled={isLoading}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isLoading ? (
              <>
                <Loader className="animate-spin h-5 w-5" />
                Scanning...
              </>
            ) : (
              'Start Scan'
            )}
          </button>
        </div>
      </form>
    </section>
  );
};

export default Scanner;