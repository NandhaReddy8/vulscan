import { useState, useEffect, useRef } from "react";
import { Loader, Shield } from "lucide-react";
import ReCAPTCHA from "react-google-recaptcha";

interface NetworkScannerFormProps {
  onSubmit: (ip: string, recaptchaToken: string) => void;
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
  const [error, setError] = useState<string | null>(null);
  const [isInputValid, setIsInputValid] = useState(false);
  const [recaptchaToken, setRecaptchaToken] = useState<string | null>(null);
  const recaptchaRef = useRef<ReCAPTCHA>(null);

  const RECAPTCHA_SITE_KEY = import.meta.env.VITE_RECAPTCHA_SITE_KEY;

  // Reset form when scan completes
  useEffect(() => {
    if (!isLoading) {
      setIp('');
      setError(null);
      setRecaptchaToken(null);
      // Reset reCAPTCHA
      if (recaptchaRef.current) {
        recaptchaRef.current.reset();
      }
    }
  }, [isLoading]);

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
  };

  const handleRecaptchaChange = (token: string | null) => {
    setRecaptchaToken(token);
    if (!token) {
      setError("Please complete the reCAPTCHA verification");
    } else if (error === "Please complete the reCAPTCHA verification") {
      setError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Prevent submission if already loading
    if (isLoading) {
      return;
    }

    // Validate input
    const validationError = validateInput(ip);
    if (validationError) {
      setError(validationError);
      return;
    }

    // Check reCAPTCHA
    if (!recaptchaToken) {
      setError("Please complete the reCAPTCHA verification");
      return;
    }

    // Submit the scan request
    onSubmit(ip, recaptchaToken);
  };

  // Don't render if no reCAPTCHA site key is configured
  if (!RECAPTCHA_SITE_KEY || RECAPTCHA_SITE_KEY === 'your_google_recaptcha_site_key_here') {
    return (
      <div className="bg-red-800/50 p-6 rounded-lg shadow-md border border-red-700 mt-8 max-w-3xl mx-auto">
        <h3 className="text-xl font-semibold text-red-300 mb-4 text-center">Configuration Required</h3>
        <p className="text-red-200 text-center">
          Google reCAPTCHA is not configured. Please set the VITE_RECAPTCHA_SITE_KEY environment variable.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="bg-gray-800 p-6 rounded-lg shadow-md border border-gray-700 mt-8 max-w-3xl mx-auto">
      <div className="flex flex-col gap-4">
        {/* Input */}
        <div className="space-y-2">
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
        </div>

        {/* reCAPTCHA */}
        <div className="flex justify-center mt-4">
          <ReCAPTCHA
            ref={recaptchaRef}
            sitekey={RECAPTCHA_SITE_KEY}
            onChange={handleRecaptchaChange}
            theme="dark"
          />
        </div>

        {/* Error Display - Only show if there's an actual error */}
        {(error || externalError) && (
          <div className="text-grey-400 text-sm mt-2 text-center">
            {error || externalError}
          </div>
        )}

        {/* Rate Limit Warning */}
        {isRateLimited && retryAfter && (
          <div className="text-yellow-400 text-sm mt-2 text-center">
            Rate limit exceeded. Please try again in {Math.ceil((retryAfter - Date.now()) / 1000)} seconds.
          </div>
        )}

        {/* Submit Button */}
        <div className="flex justify-center mt-6">
          <button
            type="submit"
            disabled={isLoading || !isInputValid || isRateLimited || !recaptchaToken}
            className={`px-8 py-2.5 bg-blue-600 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm font-medium shadow-lg hover:shadow-blue-500/20 ${
              isLoading ? 'bg-blue-700' : 'hover:bg-blue-700'
            }`}
          >
            {isLoading ? (
              <>
                <Loader className="animate-spin h-4 w-4" />
                Scanning in Progress...
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