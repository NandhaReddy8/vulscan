import { useState, useEffect } from "react"
import { useNavigate, useLocation } from "react-router-dom"
import { Card, CardContent } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Loader, StopCircle, CheckCircle2 } from "lucide-react"

// Get backend URL from environment variables
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

interface ScanResult {
  status: 'queued' | 'pending' | 'running' | 'completed' | 'failed' | 'stopped';
  results?: {
    summary: {
      total_ports: number;
      open_ports: number;
      scan_timestamp: string;
    };
    ports: Array<{
      port: string;
      protocol: string;
      state: string;
      service: string;
    }>;
    host_info: {
      hostname: string;
    };
    scan_time: string;
  };
  error?: string;
}

interface NetworkScannerProps {
  onScanSubmit: (ip: string) => void;
  onStopScan: () => void;
  isLoading: boolean;
  ip: string;
  setIp: (ip: string) => void;
  scanId: string;
}

const NetworkScanner: React.FC<NetworkScannerProps> = ({
  onScanSubmit,
  onStopScan,
  isLoading,
  ip,
  setIp,
  scanId,
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<string | null>(null);
  const [captcha, setCaptcha] = useState({ num1: 0, num2: 0, operation: "+", answer: "" });
  const [attempts, setAttempts] = useState(5);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [pollingInterval, setPollingInterval] = useState<NodeJS.Timeout | null>(null);

  // Generate a new CAPTCHA
  const generateCaptcha = () => {
    let num1 = Math.floor(Math.random() * 20) + 1;
    let num2 = Math.floor(Math.random() * 20) + 1;
    const operation = Math.random() > 0.5 ? "+" : "-";

    if (operation === "-" && num1 < num2) {
      [num1, num2] = [num2, num1];
    }

    setCaptcha({ num1, num2, operation, answer: "" });
  };

  useEffect(() => {
    generateCaptcha();
    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, []);

  // Poll for scan results
  useEffect(() => {
    if (scanId && !['completed', 'failed', 'stopped'].includes(scanResult?.status || '')) {
      const interval = setInterval(async () => {
        try {
          const response = await fetch(`${BACKEND_URL}/api/network/scan/${scanId}`, {
            headers: {
              'X-Requester-IP': window.location.hostname
            }
          });
          if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to fetch scan results');
          }
          
          const data = await response.json();
          console.log('Received scan data:', data);
          
          // Update scan result with the data directly
          setScanResult({
            status: data.scan_status,
            results: data.scan_results,
            error: data.error_message
          });
          
          // Stop polling if scan is in a terminal state
          if (['completed', 'failed', 'stopped'].includes(data.scan_status)) {
            console.log('Scan reached terminal state:', data.scan_status);
            clearInterval(interval);
            setPollingInterval(null);
            // Also stop the scan if it's still running
            if (data.scan_status === 'running') {
              handleStopScan();
            }
          }
        } catch (error) {
          console.error('Error polling scan results:', error);
          if (error instanceof Error) {
            setError(error.message);
          }
          // Stop polling on error
          clearInterval(interval);
          setPollingInterval(null);
        }
      }, 2000); // Poll every 2 seconds
      
      setPollingInterval(interval);
      return () => {
        clearInterval(interval);
        setPollingInterval(null);
      };
    }
  }, [scanId, scanResult?.status]);

  const handleStopScan = async () => {
    if (!scanId) return;
    
    try {
      const response = await fetch(`${BACKEND_URL}/api/network/stop-scan/${scanId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requester-IP': window.location.hostname
        }
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to stop scan');
      }

      const data = await response.json();
      console.log('Stop scan response:', data);
      
      // Update scan status to stopped
      setScanResult(prev => ({
        ...prev,
        status: 'stopped',
        error: 'Scan stopped by user'
      }));

      // Clear polling interval
      if (pollingInterval) {
        clearInterval(pollingInterval);
        setPollingInterval(null);
      }

      // Call the parent's onStopScan handler
      onStopScan();
    } catch (error) {
      console.error('Error stopping scan:', error);
      if (error instanceof Error) {
        setError(error.message);
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setScanResult(null);

    const correctAnswer =
      captcha.operation === "+"
        ? captcha.num1 + captcha.num2
        : captcha.num1 - captcha.num2;

    if (Number(captcha.answer) !== correctAnswer) {
      setError("Incorrect CAPTCHA answer. Please try again.");
      setAttempts((prev) => prev - 1);

      if (attempts - 1 <= 0) {
        setError("Too many failed attempts. Please try again later.");
        return;
      }

      generateCaptcha();
      return;
    }

    setAttempts(5);
    generateCaptcha();

    // Validate IP address format
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      setError("Please enter a valid IP address (e.g., 192.168.1.1)");
      return;
    }

    // Validate each octet
    const octets = ip.split('.');
    const isValid = octets.every(octet => {
      const num = parseInt(octet);
      return num >= 0 && num <= 255;
    });

    if (!isValid) {
      setError("Each number in the IP address must be between 0 and 255");
      return;
    }

    // Use the onScanSubmit prop instead of making our own request
    onScanSubmit(ip);
    setScanResult({ status: 'queued' });
  };

  const handleIpChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const input = e.target.value;
    // Only allow numbers and dots
    const validInput = input.replace(/[^\d.]/g, "");
    setIp(validInput);
  };

  const renderScanResults = () => {
    if (!scanResult) return null;

    // Show loading state for pending/running scans
    if (scanResult.status === 'pending' || scanResult.status === 'running') {
      return (
        <Alert variant="info" className="mb-4">
          <div className="flex items-center gap-2">
            <Loader className="animate-spin h-4 w-4" />
            <AlertDescription>Scan in progress... Please wait while we analyze the target.</AlertDescription>
          </div>
        </Alert>
      );
    }

    // Show error state
    if (scanResult.status === 'failed') {
      return (
        <Alert variant="destructive" className="mb-4">
          <AlertDescription>
            {scanResult.error || "Scan failed. Please try again."}
          </AlertDescription>
        </Alert>
      );
    }

    // Show completed scan results
    if (scanResult.status === 'completed' && scanResult.results) {
      const { summary, ports, host_info } = scanResult.results;
      return (
        <Card className="mt-4 bg-gray-800/50 border-gray-700">
          <CardContent className="p-6">
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle2 className="h-5 w-5 text-green-400" />
              <h3 className="text-lg font-semibold text-white">Scan Results</h3>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <div className="bg-gray-700/50 p-4 rounded-lg">
                <h4 className="text-sm font-medium text-gray-300 mb-2">Host Information</h4>
                <p className="text-white">{host_info?.hostname || 'Unknown'}</p>
              </div>
              
              <div className="bg-gray-700/50 p-4 rounded-lg">
                <h4 className="text-sm font-medium text-gray-300 mb-2">Scan Summary</h4>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <p className="text-sm text-gray-400">Total Ports</p>
                    <p className="text-white font-medium">{summary?.total_ports || 0}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Open Ports</p>
                    <p className="text-white font-medium">{summary?.open_ports || 0}</p>
                  </div>
                </div>
              </div>
            </div>

            {ports && ports.length > 0 ? (
              <div>
                <h4 className="text-sm font-medium text-gray-300 mb-2">Open Ports</h4>
                <div className="bg-gray-700/50 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="bg-gray-800/50">
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">Port</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">Protocol</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">State</th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">Service</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ports.map((port, index) => (
                        <tr key={index} className="border-t border-gray-700/50">
                          <td className="px-4 py-2 text-sm text-white">{port.port}</td>
                          <td className="px-4 py-2 text-sm text-white">{port.protocol}</td>
                          <td className="px-4 py-2 text-sm">
                            <span className={`px-2 py-1 rounded-full text-xs ${
                              port.state === 'open' ? 'bg-green-900/50 text-green-400' : 'bg-gray-900/50 text-gray-400'
                            }`}>
                              {port.state}
                            </span>
                          </td>
                          <td className="px-4 py-2 text-sm text-white">{port.service}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <Alert variant="info" className="mb-4">
                <AlertDescription>No open ports found</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      );
    }

    return null;
  };

  return (
    <section className="max-w-3xl mx-auto mb-16 mt-16" data-aos="fade-up">
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
        className="bg-gray-800 p-6 rounded-lg shadow-md border border-gray-700 mt-8"
      >
        <div className="flex flex-col gap-4">
          <div className="flex gap-2">
            <input
              type="text"
              value={ip}
              onChange={handleIpChange}
              placeholder="Enter IP address (e.g., 192.168.1.1)"
              className="flex-1 px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/30 transition-all text-base"
              required
              disabled={isLoading || scanResult?.status === 'running'}
              aria-label="IP Address"
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
                disabled={isLoading || scanResult?.status === 'running'}
                aria-label="CAPTCHA Answer"
                placeholder="Answer"
              />
            </div>
          </div>

          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <p className="text-gray-300 text-sm mb-4">
            Attempts remaining: <strong>{attempts}</strong>
          </p>

          <div className="flex justify-center gap-4">
            <button
              type="submit"
              disabled={isLoading || attempts <= 0 || scanResult?.status === 'running'}
              className="px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm"
            >
              {isLoading || scanResult?.status === 'running' ? (
                <>
                  <Loader className="animate-spin h-4 w-4" />
                  Scanning...
                </>
              ) : (
                "Start Network Scan"
              )}
            </button>

            {(isLoading || scanResult?.status === 'running') && (
              <button
                type="button"
                onClick={handleStopScan}
                className="px-3 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors flex items-center gap-2 text-sm"
              >
                <StopCircle className="h-4 w-4" />
                Stop Scan
              </button>
            )}
          </div>
        </div>
      </form>

      {renderScanResults()}
    </section>
  );
};

export default NetworkScanner; 