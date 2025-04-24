import React, { useState } from "react";
import { Loader, StopCircle } from "lucide-react";

interface ScannerProps {
  onScanSubmit: (url: string) => void;
  onStopScan: () => void;
  isLoading: boolean;
  url: string;
  setUrl: (url: string) => void;
}

const Scanner: React.FC<ScannerProps> = ({
  onScanSubmit,
  onStopScan,
  isLoading,
  url,
  setUrl,
}) => {
  const [protocol, setProtocol] = useState("https://");
  const [error, setError] = useState<string | null>(null);
  const [captcha, setCaptcha] = useState({ num1: 0, num2: 0, operation: "+", answer: "" });
  const [attempts, setAttempts] = useState(5);
  const [scannerType, setScannerType] = useState<'application' | 'network'>('application');

  // Generate a new CAPTCHA
  const generateCaptcha = () => {
    let num1 = Math.floor(Math.random() * 20) + 1;
    let num2 = Math.floor(Math.random() * 20) + 1;
    const operation = Math.random() > 0.5 ? "+" : "-";

    // Ensure subtraction results in a positive answer
    if (operation === "-" && num1 < num2) {
      [num1, num2] = [num2, num1];
    }

    setCaptcha({ num1, num2, operation, answer: "" });
  };

  // Initialize CAPTCHA on component mount
  React.useEffect(() => {
    generateCaptcha();
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate CAPTCHA
    const correctAnswer =
      captcha.operation === "+"
        ? captcha.num1 + captcha.num2
        : captcha.num1 - captcha.num2;

    if (Number(captcha.answer) !== correctAnswer) {
      setError("Incorrect CAPTCHA answer. Please try again.");
      setAttempts((prev) => prev - 1);

      // Block after 0 attempts
      if (attempts - 1 <= 0) {
        setError("Too many failed attempts. Please try again later.");
        return;
      }

      generateCaptcha(); // Generate a new problem even if the answer is wrong
      return;
    }

    // If CAPTCHA is correct, reset attempts and generate a new problem
    setAttempts(5);
    generateCaptcha();

    // Proceed with the scan
    const fullUrl = `${protocol}${url}`;
    onScanSubmit(fullUrl);
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const input = e.target.value;
    const validInput = input.replace(/[^a-zA-Z0-9.-]/g, "");
    setUrl(validInput);
  };

  return (
    <section className="max-w-3xl mx-auto mb-16 mt-16" data-aos="fade-up">
      {/* Scanner Type Selection */}
      <div className="flex gap-4 mb-6 justify-center">
        <button
          type="button"
          onClick={() => setScannerType('application')}
          className={`px-6 py-3 rounded-lg font-medium transition-all ${
            scannerType === 'application'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          Application Scanner
        </button>
        <div className="relative group">
          <button
            type="button"
            disabled
            className="px-6 py-3 rounded-lg font-medium bg-gray-700 text-gray-400 cursor-not-allowed opacity-75"
          >
            Network Scanner
          </button>
          <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-1 bg-gray-900 text-white text-sm rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap">
            Coming Soon!
          </div>
        </div>
        <div className="relative group">
          <button
            type="button"
            disabled
            className="px-6 py-3 rounded-lg font-medium bg-gray-700 text-gray-400 cursor-not-allowed opacity-75"
          >
            API Scanner
          </button>
          <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-1 bg-gray-900 text-white text-sm rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 whitespace-nowrap">
            Coming Soon!
          </div>
        </div>
      </div>

      <form
        onSubmit={handleSubmit}
        className="bg-gray-800 p-6 rounded-lg shadow-md border border-gray-700 mt-8"
      >
        <div className="flex flex-col gap-4">
          <div className="flex gap-2">
        <select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value)}
          className="px-3 py-2 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all text-sm"
        >
          <option value="http://">http://</option>
          <option value="https://">https://</option>
        </select>
        <input
          type="text"
          value={url}
          onChange={handleUrlChange}
          placeholder="Enter site name (e.g., example.com)"
          className="flex-1 px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all text-base"
          required
        />
          </div>

          <div className="flex items-center justify-between bg-gray-700 p-2 rounded-lg border border-gray-600 shadow-md">
        <p className="text-sm font-medium text-gray-300">
          Solve the CAPTCHA to proceed
        </p>
        <div className="flex items-center justify-center gap-2 bg-gray-800 px-4 py-2 rounded-lg shadow-md border border-gray-600">
          <span className="text-lg font-bold text-gray-100">
            {captcha.num1}
          </span>
          <span className="text-lg font-bold text-blue-400">
            {captcha.operation}
          </span>
          <span className="text-lg font-bold text-gray-100">
            {captcha.num2}
          </span>
          <span className="text-lg font-bold text-gray-100">=</span>
          <input
            type="number"
            value={captcha.answer}
            onChange={(e) => setCaptcha({ ...captcha, answer: e.target.value })}
            className="w-20 px-3 py-2 text-center text-sm font-medium rounded-lg bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all"
            required
          />
        </div>
          </div>

          {error && <div className="text-red-400 text-xs mt-2">{error}</div>}

          <p className="text-gray-300 text-sm mb-4">
        Attempts remaining: <strong>{attempts}</strong>
          </p>

          <div className="flex justify-center gap-4">
        <button
          type="submit"
          disabled={isLoading || attempts <= 0}
          className="px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm"
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

        {isLoading && (
          <button
            type="button"
            onClick={onStopScan}
            className="px-3 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors flex items-center gap-2 text-sm"
          >
            <StopCircle className="h-4 w-4" />
            Stop Scan
          </button>
        )}
          </div>
        </div>
      </form>
    </section>
  );
};

export default Scanner;
