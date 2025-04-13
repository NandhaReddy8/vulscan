import React, { useState } from "react";
import { Loader } from "lucide-react";

interface ScannerProps {
  onScanSubmit: (url: string) => void; // Removed email parameter
  isLoading: boolean;
  url: string;
  setUrl: (url: string) => void;
}

const Scanner: React.FC<ScannerProps> = ({
  onScanSubmit,
  isLoading,
  url,
  setUrl,
}) => {
  const [activeType, setActiveType] = useState<"network" | "application">("application");
  const [protocol, setProtocol] = useState("https://");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    try {
        const fullUrl = `${protocol}${url}`;
        // Submit scan with just the URL
        onScanSubmit(fullUrl);
    } catch (error) {
        setError("Invalid URL format. Please check your input.");
    }
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const input = e.target.value;
    // Allow only valid characters for a domain name
    const validInput = input.replace(/[^a-zA-Z0-9.-]/g, "");
    setUrl(validInput);
  };

  return (
    <section className="max-w-3xl mx-auto mb-16 mt-16" data-aos="fade-up">
      <div className="flex justify-center gap-4 mb-8">
        <button
          className={`px-6 py-3 rounded-lg transition-colors ${
            activeType === "application"
              ? "bg-blue-600 text-white"
              : "bg-gray-700 text-gray-200 hover:bg-gray-600"
          }`}
          onClick={() => setActiveType("application")}
        >
          Application Scanning
        </button>
        <div className="relative group">
          <button
            className="px-6 py-3 rounded-lg bg-gray-700 text-gray-400 cursor-not-allowed"
            disabled
          >
            Network Scanning
          </button>
          <div className="absolute -top-8 left-1/2 transform -translate-x-1/2 bg-gray-900 text-white text-sm px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap">
            Coming Soon
          </div>
        </div>
      </div>

      <form
        onSubmit={handleSubmit}
        className="bg-gray-800 p-8 rounded-lg shadow-md border border-gray-700 mt-8"
      >
        <div className="flex flex-col gap-4">
          <div className="flex gap-2">
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all"
            >
              <option value="http://">http://</option>
              <option value="https://">https://</option>
            </select>
            <input
              type="text"
              value={url}
              onChange={handleUrlChange}
              placeholder="Enter site name (e.g., example.com)"
              className="flex-1 px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all"
              required
            />
          </div>
          {error && (
            <div className="text-red-400 text-sm mt-2">{error}</div>
          )}
          <div className="flex justify-center">
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {isLoading ? (
                <>
                  <Loader className="animate-spin h-4 w-4" />
                  Scanning...
                </>
              ) : (
                "Start Scan"
              )}
            </button>
          </div>
        </div>
      </form>
    </section>
  );
};

export default Scanner;
