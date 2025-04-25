import React from 'react';
import { useNavigate } from 'react-router-dom';

const ScannerRedirect: React.FC = () => {
  const navigate = useNavigate();

  const handleScannerRedirect = () => {
    window.location.href = '/webscanner';
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white">
      <h1 className="text-4xl font-bold mb-8">VirtuesTech Security Solutions</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
        <button
          onClick={handleScannerRedirect}
          className="p-6 rounded-lg bg-blue-600 hover:bg-blue-700 transition-colors"
        >
          <h3 className="text-xl font-semibold mb-2">Application Scanner</h3>
          <p className="text-sm opacity-80">
            Scan web applications for vulnerabilities
          </p>
        </button>

        <button
          disabled
          className="p-6 rounded-lg bg-gray-800 text-gray-400 cursor-not-allowed relative group"
        >
          <h3 className="text-xl font-semibold mb-2">Network Scanner</h3>
          <p className="text-sm opacity-80">Coming Soon</p>
        </button>

        <button
          disabled
          className="p-6 rounded-lg bg-gray-800 text-gray-400 cursor-not-allowed relative group"
        >
          <h3 className="text-xl font-semibold mb-2">API Scanner</h3>
          <p className="text-sm opacity-80">Coming Soon</p>
        </button>
      </div>
    </div>
  );
};

export default ScannerRedirect;