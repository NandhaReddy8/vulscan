import React, { useState, useEffect } from "react";
import { Loader, StopCircle, CheckCircle2 } from "lucide-react";
import { useNavigate, useLocation } from "react-router-dom";
import CapCaptcha from './CapCaptcha';
import { Alert, AlertDescription } from "@/components/ui/alert";

interface ScannerProps {
  onScanSubmit: (url: string, captchaToken: string) => void;
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
  const navigate = useNavigate();
  const location = useLocation();
  const [protocol, setProtocol] = useState("https://");
  const [error, setError] = useState<string | null>(null);
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [showCaptcha, setShowCaptcha] = useState(false);
  const [isInputValid, setIsInputValid] = useState(false);

  // Validate input whenever it changes
  useEffect(() => {
    const validationError = validateInput(url);
    // Only set isInputValid to true if there's no error AND the input is not empty
    setIsInputValid(!validationError && url.trim().length > 0);
    setError(validationError);
  }, [url]);

  const validateInput = (input: string): string | null => {
    // Return error for empty input
    if (!input.trim()) {
      return "Please enter a website URL";
    }
    
    // Remove any protocol prefix if present
    input = input.replace(/^https?:\/\//, '').trim();
    
    // Check if it's a valid domain name
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(input)) {
      return "Please enter a valid domain name (e.g., example.com)";
    }
    
    return null;
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const input = e.target.value;
    // Remove any protocol prefix if present
    const cleanUrl = input.replace(/^https?:\/\//, '');
    setUrl(cleanUrl);
    setShowCaptcha(false); // Hide CAPTCHA when input changes
    setCaptchaToken(null); // Clear CAPTCHA token
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate input
    const validationError = validateInput(url);
    if (validationError) {
      setError(validationError);
      return;
    }

    // Check if we have a valid CAPTCHA token
    if (!captchaToken) {
      setError("Please complete the proof-of-work verification");
      return;
    }

    // Proceed with the scan
    const fullUrl = `${protocol}${url}`;
    onScanSubmit(fullUrl, captchaToken);
  };

  return (
    <section className="text-center" data-aos="fade-up">
      {/* Scanner Type Selection */}
      <div className="flex gap-4 mb-6 justify-center">
        <button
          type="button"
          onClick={() => navigate('/webscanner')}
          className={`px-6 py-3 rounded-lg font-medium transition-all ${
            location.pathname === '/webscanner'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          Application Scanner
        </button>
        <button
          type="button"
          onClick={() => navigate('/networkscanner')}
          className={`px-6 py-3 rounded-lg font-medium transition-all ${
            location.pathname === '/networkscanner'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          Network Scanner
        </button>
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
        className="bg-gray-800 p-6 rounded-lg shadow-md border border-gray-700 mt-8 max-w-3xl mx-auto"
      >
        <div className="flex flex-col gap-4">
          {/* Step 1: Input */}
          <div className="space-y-2">
            <label htmlFor="url-input" className="text-sm font-medium text-gray-300">
              Step 1: Enter Target URL
            </label>
            <div className="flex gap-2">
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="px-3 py-2 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all text-sm"
                aria-label="Protocol"
                title="Select protocol"
              >
                <option value="http://">http://</option>
                <option value="https://">https://</option>
              </select>
              <input
                id="url-input"
                type="text"
                value={url}
                onChange={handleUrlChange}
                placeholder="Enter site name (e.g., example.com)"
                className="flex-1 px-4 py-2 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all text-base"
                required
                disabled={isLoading}
                aria-label="Website URL"
                title="Enter website URL"
              />
            </div>
            {isInputValid && !showCaptcha && (
              <button
                type="button"
                onClick={() => setShowCaptcha(true)}
                className="mt-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors flex items-center gap-2 text-sm"
              >
                <CheckCircle2 className="h-4 w-4" />
                Verify CAPTCHA
              </button>
            )}
          </div>

          {/* Step 2: CAPTCHA */}
          {showCaptcha && (
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">
                Step 2: Complete Verification
              </label>
              <CapCaptcha
                onVerified={(token) => {
                  setCaptchaToken(token);
                  setError(null);
                }}
                onError={(error) => {
                  setError(error);
                  setCaptchaToken(null);
                }}
              />
            </div>
          )}

          {/* Error Display */}
          {error && (
            <Alert variant="destructive" className="mt-2">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {/* Submit Button */}
          <div className="flex justify-center mt-6">
            {isLoading ? (
              <button
                type="button"
                onClick={onStopScan}
                className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors flex items-center gap-2 text-sm"
              >
                <StopCircle className="h-4 w-4" />
                Stop Scan
              </button>
            ) : (
              <button
                type="submit"
                disabled={isLoading || !captchaToken || !isInputValid}
                className="px-8 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm font-medium shadow-lg hover:shadow-blue-500/20"
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
            )}
          </div>
        </div>
      </form>
    </section>
  );
};

export default Scanner;
