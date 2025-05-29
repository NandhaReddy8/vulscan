import { useState, useEffect } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader, Shield, CheckCircle2 } from "lucide-react";
import CapCaptcha from './CapCaptcha';

interface NetworkScannerFormProps {
  onSubmit: (ip: string, captchaToken: string) => void;
  isLoading: boolean;
  isRateLimited: boolean;
  retryAfter: number | null;
  error: string | null;
}

const NetworkScannerForm: React.FC<NetworkScannerFormProps> = ({
  onSubmit,
  isLoading,
  isRateLimited,
  retryAfter,
  error: externalError
}) => {
  const [ip, setIp] = useState("");
  const [showCaptcha, setShowCaptcha] = useState(false);
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isInputValid, setIsInputValid] = useState(false);

  // Validate input whenever it changes
  useEffect(() => {
    const validationError = validateInput(ip);
    // Only set isInputValid to true if there's no error AND the input is not empty
    setIsInputValid(!validationError && ip.trim().length > 0);
    setError(validationError);
  }, [ip]);

  const validateInput = (input: string): string | null => {
    // Return error for empty input
    if (!input.trim()) {
      return "Please enter an IP address or domain name";
    }
    
    // Remove any protocol prefix if present
    input = input.replace('http://', '').replace('https://', '').trim();
    
    // Check if it's a domain name
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (domainRegex.test(input)) {
      return null; // Valid domain name
    }
    
    // Check if it's an IP address
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(input)) {
      return "Please enter a valid IP address (e.g., 8.8.8.8) or domain name (e.g., example.com)";
    }
    
    // Validate each octet
    const octets = input.split('.');
    const isValid = octets.every(octet => {
      const num = parseInt(octet);
      return num >= 0 && num <= 255;
    });
    
    if (!isValid) {
      return "Each number in the IP address must be between 0 and 255";
    }
    
    return null;
  };

  const handleIpChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const input = e.target.value;
    // Allow letters, numbers, dots, and hyphens for domain names
    const validInput = input.replace(/[^a-zA-Z0-9.-]/g, "");
    setIp(validInput);
    setShowCaptcha(false); // Hide CAPTCHA when input changes
    setCaptchaToken(null); // Clear CAPTCHA token
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate input
    const validationError = validateInput(ip);
    if (validationError) {
      setError(validationError);
      return;
    }

    // Check if we have a valid CAPTCHA token
    if (!captchaToken) {
      setError("Please complete the proof-of-work verification");
      return;
    }

    // Submit the scan request
    onSubmit(ip, captchaToken);
  };

  return (
    <form onSubmit={handleSubmit} className="bg-gray-800 p-6 rounded-lg shadow-md border border-gray-700 mt-8 max-w-3xl mx-auto">
      <div className="flex flex-col gap-4">
        {/* Step 1: Input */}
        <div className="space-y-2">
          <label htmlFor="ip-input" className="text-sm font-medium text-gray-300">
            Step 1: Enter Target
          </label>
          <div className="flex gap-2">
            <input
              id="ip-input"
              type="text"
              value={ip}
              onChange={handleIpChange}
              placeholder="Enter IP address (e.g., 8.8.8.8) or domain name (e.g., example.com)"
              className="flex-1 px-4 py-2 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all text-base"
              required
              disabled={isLoading}
              aria-label="Target Address"
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
        {(error || externalError) && (
          <Alert variant="destructive" className="mt-2">
            <AlertDescription>
              {error || externalError}
            </AlertDescription>
          </Alert>
        )}

        {/* Rate Limit Warning */}
        {isRateLimited && retryAfter && (
          <Alert variant="warning" className="mt-2">
            <AlertDescription>
              Rate limit exceeded. Please try again in {Math.ceil((retryAfter - Date.now()) / 1000)} seconds.
            </AlertDescription>
          </Alert>
        )}

        {/* Submit Button */}
        <div className="flex justify-center mt-6">
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
              <>
                <Shield className="h-4 w-4" />
                Start Network Scan
              </>
            )}
          </button>
        </div>
      </div>
    </form>
  );
};

export default NetworkScannerForm; 