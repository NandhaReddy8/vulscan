import { useState, useEffect } from "react"
import { useNavigate, useLocation } from "react-router-dom"
import { Card, CardContent } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { 
  Loader, 
  StopCircle, 
  Shield, 
  Server, 
  Network, 
  AlertTriangle, 
  Lock, 
  Clock, 
  Activity, 
  AlertCircle,
  ExternalLink
} from "lucide-react"
import { Progress } from "@/components/ui/progress"

// Get backend URL from environment variables
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

interface ScanResult {
  status: 'queued' | 'pending' | 'running' | 'completed' | 'failed' | 'stopped';
  results?: {
    summary: {
      total_hosts: number;
      up_hosts: number;
      scan_timestamp: string;
    };
    hosts: Array<{
      hostname: string;
      ip: string;
      status: 'up' | 'down';
      os_info: {
        details?: string;
        cpe?: string;
      };
      ports: Array<{
        port: string;
        protocol: string;
        state: string;
        service: string;
        version?: string;
        scripts?: Record<string, string>;
      }>;
      latency?: number;
      filtered_ports: number;
    }>;
    scan_time: string;
  };
  error?: string;
}

interface NetworkScannerProps {
  onScanSubmit: (ip: string) => void;
  onStopScan: () => void;
  ip: string;
  setIp: (ip: string) => void;
  scanId: string;
}

const NetworkScanner: React.FC<NetworkScannerProps> = ({
  onScanSubmit,
  onStopScan,
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
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);

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

  // Update polling effect to handle progress
  useEffect(() => {
    if (scanId && !['completed', 'failed', 'stopped'].includes(scanResult?.status || '')) {
      setIsScanning(true);
      // Start progress animation
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 90) return prev; // Cap at 90% until complete
          return prev + 1;
        });
      }, 1000);

      const interval = setInterval(async () => {
        try {
          const response = await fetch(`${BACKEND_URL}/api/network/scan/${scanId}`);
          if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to fetch scan results');
          }
          
          const data = await response.json();
          console.log('Received scan data:', data);
          
          setScanResult({
            status: data.scan_status,
            results: data.scan_results,
            error: data.error_message
          });
          
          if (['completed', 'failed', 'stopped'].includes(data.scan_status)) {
            console.log('Scan reached terminal state:', data.scan_status);
            clearInterval(interval);
            clearInterval(progressInterval);
            setPollingInterval(null);
            setIsScanning(false);
            setScanProgress(100); // Set to 100% when complete
            // Reset progress after a delay
            setTimeout(() => setScanProgress(0), 1000);
            if (data.scan_status === 'running') {
              handleStopScan();
            }
          }
        } catch (error) {
          console.error('Error polling scan results:', error);
          if (error instanceof Error) {
            setError(error.message);
          }
          clearInterval(interval);
          clearInterval(progressInterval);
          setPollingInterval(null);
          setIsScanning(false);
          setScanProgress(0);
        }
      }, 2000);
      
      setPollingInterval(interval);
      return () => {
        clearInterval(interval);
        clearInterval(progressInterval);
        setPollingInterval(null);
        setIsScanning(false);
        setScanProgress(0);
      };
    }
  }, [scanId, scanResult?.status]);

  const handleStopScan = async () => {
    if (!scanId) return;
    
    try {
      const response = await fetch(`${BACKEND_URL}/api/network/stop-scan/${scanId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
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
      const { summary, hosts, scan_time } = scanResult.results;
      return (
        <div className="space-y-6">
          {/* Executive Summary Card */}
          <Card className="bg-gray-800/50 border-gray-700">
            <CardContent className="p-6">
              <div className="flex items-center gap-2 mb-6">
                <Shield className="h-6 w-6 text-blue-400 flex-shrink-0" />
                <h3 className="text-xl font-semibold text-white">Security Assessment Summary</h3>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-gray-700/50 p-4 rounded-lg min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <Server className="h-4 w-4 text-blue-400 flex-shrink-0" />
                    <h4 className="text-sm font-medium text-gray-300">Target Status</h4>
                  </div>
                  <div className="space-y-1">
                    <div>
                      <p className="text-sm text-gray-400">Hostname</p>
                      <p className="text-white font-medium break-words whitespace-normal">
                        {hosts[0]?.hostname || 'Unknown'}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400">IP Address</p>
                      <p className="text-white font-medium">{hosts[0]?.ip || 'Unknown'}</p>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400">Status</p>
                      <p className={`font-medium ${hosts[0]?.status === 'up' ? 'text-green-400' : 'text-red-400'}`}>
                        {hosts[0]?.status?.toUpperCase() || 'UNKNOWN'}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="bg-gray-700/50 p-4 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Activity className="h-4 w-4 text-blue-400" />
                    <h4 className="text-sm font-medium text-gray-300">Network Analysis</h4>
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm text-gray-400">Response Time</p>
                    <p className="text-white font-medium">{hosts[0]?.latency || '0'} seconds</p>
                    <p className="text-sm text-gray-400">Open Ports</p>
                    <p className="text-white font-medium">{hosts[0]?.ports?.length || 0}</p>
                    <p className="text-sm text-gray-400">Filtered Ports</p>
                    <p className="text-white font-medium">{hosts[0]?.filtered_ports || 0}</p>
                  </div>
                </div>

                <div className="bg-gray-700/50 p-4 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-4 w-4 text-blue-400" />
                    <h4 className="text-sm font-medium text-gray-300">Risk Assessment</h4>
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm text-gray-400">Critical Services</p>
                    <p className="text-white font-medium">
                      {hosts[0]?.ports?.filter(p => 
                        ['ssh', 'ftp', 'telnet', 'smtp', 'http', 'https'].includes(p.service?.toLowerCase())
                      ).length || 0}
                    </p>
                    <p className="text-sm text-gray-400">SSL/TLS Services</p>
                    <p className="text-white font-medium">
                      {hosts[0]?.ports?.filter(p => 
                        p.scripts && Object.keys(p.scripts).some(k => k.includes('ssl'))
                      ).length || 0}
                    </p>
                  </div>
                </div>

                <div className="bg-gray-700/50 p-4 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Clock className="h-4 w-4 text-blue-400" />
                    <h4 className="text-sm font-medium text-gray-300">Scan Information</h4>
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm text-gray-400">Scan Duration</p>
                    <p className="text-white font-medium">{scan_time}</p>
                    <p className="text-sm text-gray-400">Scan Timestamp</p>
                    <p className="text-white font-medium">{new Date(summary.scan_timestamp).toLocaleString()}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Detailed Analysis */}
          {hosts.map((host, hostIndex) => (
            <div key={hostIndex} className="space-y-4">
              {/* Operating System Information */}
              {host.os_info && Object.keys(host.os_info).length > 0 && (
                <Card className="bg-gray-800/50 border-gray-700">
                  <CardContent className="p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <Server className="h-5 w-5 text-blue-400 flex-shrink-0" />
                      <h3 className="text-lg font-semibold text-white">Operating System Analysis</h3>
                    </div>
                    <div className="bg-gray-700/50 p-4 rounded-lg">
                      {host.os_info.details && (
                        <div className="mb-2 break-words">
                          <p className="text-sm text-gray-400">OS Details</p>
                          <p className="text-white whitespace-pre-wrap">{host.os_info.details}</p>
                        </div>
                      )}
                      {host.os_info.cpe && (
                        <div className="break-words">
                          <p className="text-sm text-gray-400">OS CPE</p>
                          <p className="text-white font-mono text-sm whitespace-pre-wrap">{host.os_info.cpe}</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Port Analysis */}
              {host.ports && host.ports.length > 0 && (
                <Card className="bg-gray-800/50 border-gray-700">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-2 min-w-0">
                        <Network className="h-5 w-5 text-blue-400 flex-shrink-0" />
                        <h3 className="text-lg font-semibold text-white truncate">Port Analysis</h3>
                      </div>
                      <div className="text-sm text-gray-400 flex-shrink-0">
                        {host.filtered_ports > 0 && (
                          <span className="flex items-center gap-1">
                            <AlertCircle className="h-4 w-4" />
                            {host.filtered_ports} ports filtered
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="space-y-4">
                      {/* Critical Services */}
                      {host.ports.filter(p => 
                        ['ssh', 'ftp', 'telnet', 'smtp', 'http', 'https'].includes(p.service?.toLowerCase())
                      ).length > 0 && (
                        <div>
                          <h4 className="text-sm font-medium text-gray-300 mb-2">Critical Services</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {host.ports
                              .filter(p => ['ssh', 'ftp', 'telnet', 'smtp', 'http', 'https'].includes(p.service?.toLowerCase()))
                              .map((port, idx) => (
                                <div key={idx} className="bg-gray-700/50 p-3 rounded-lg min-w-0">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-sm font-medium text-white break-words whitespace-normal">
                                      {port.service.toUpperCase()}
                                    </span>
                                    <span className="text-xs px-2 py-1 rounded-full bg-blue-900/50 text-blue-400 flex-shrink-0 ml-2">
                                      Port {port.port}/{port.protocol}
                                    </span>
                                  </div>
                                  {port.version && (
                                    <p className="text-sm text-gray-300 break-words whitespace-normal">{port.version}</p>
                                  )}
                                  {port.scripts && Object.entries(port.scripts).map(([script, output], scriptIdx) => (
                                    <div key={scriptIdx} className="mt-2">
                                      <p className="text-xs text-gray-400 break-words whitespace-normal">{script}</p>
                                      <div className="mt-1 overflow-hidden">
                                        <pre className="text-xs text-gray-300 whitespace-pre-wrap break-words font-mono bg-gray-800/50 p-2 rounded max-w-full">
                                          {output}
                                        </pre>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              ))}
                          </div>
                        </div>
                      )}

                      {/* Other Services */}
                      {host.ports.filter(p => 
                        !['ssh', 'ftp', 'telnet', 'smtp', 'http', 'https'].includes(p.service?.toLowerCase())
                      ).length > 0 && (
                        <div>
                          <h4 className="text-sm font-medium text-gray-300 mb-2">Other Services</h4>
                          <div className="bg-gray-700/50 rounded-lg overflow-x-auto">
                            <table className="w-full min-w-[600px]">
                              <thead>
                                <tr className="bg-gray-800/50">
                                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">Port</th>
                                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">Service</th>
                                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">State</th>
                                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-400">Version</th>
                                </tr>
                              </thead>
                              <tbody>
                                {host.ports
                                  .filter(p => !['ssh', 'ftp', 'telnet', 'smtp', 'http', 'https'].includes(p.service?.toLowerCase()))
                                  .map((port, idx) => (
                                    <tr key={idx} className="border-t border-gray-700/50">
                                      <td className="px-4 py-2 text-sm text-white whitespace-nowrap">
                                        {port.port}/{port.protocol}
                                      </td>
                                      <td className="px-4 py-2 text-sm text-white break-words whitespace-normal max-w-[200px]">
                                        {port.service}
                                      </td>
                                      <td className="px-4 py-2 text-sm whitespace-nowrap">
                                        <span className={`px-2 py-1 rounded-full text-xs ${
                                          port.state === 'open' ? 'bg-green-900/50 text-green-400' : 'bg-gray-900/50 text-gray-400'
                                        }`}>
                                          {port.state}
                                        </span>
                                      </td>
                                      <td className="px-4 py-2 text-sm text-white break-words whitespace-normal max-w-[200px]">
                                        {port.version || '-'}
                                      </td>
                                    </tr>
                                  ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Security Recommendations */}
              <Card className="bg-gray-800/50 border-gray-700">
                <CardContent className="p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <Lock className="h-5 w-5 text-blue-400 flex-shrink-0" />
                    <h3 className="text-lg font-semibold text-white">Security Recommendations</h3>
                  </div>
                  <div className="space-y-4">
                    {/* Generate recommendations based on scan results */}
                    {host.ports.some(p => p.service?.toLowerCase() === 'ssh') && (
                      <div className="bg-gray-700/50 p-4 rounded-lg break-words">
                        <h4 className="text-sm font-medium text-gray-300 mb-2">SSH Security</h4>
                        <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                          <li>Ensure SSH is configured to use strong encryption</li>
                          <li>Disable root login if enabled</li>
                          <li>Use key-based authentication instead of passwords</li>
                        </ul>
                      </div>
                    )}
                    
                    {host.ports.some(p => ['http', 'https'].includes(p.service?.toLowerCase())) && (
                      <div className="bg-gray-700/50 p-4 rounded-lg break-words">
                        <h4 className="text-sm font-medium text-gray-300 mb-2">Web Server Security</h4>
                        <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                          <li>Ensure HTTPS is enabled for all web services</li>
                          <li>Keep web server software up to date</li>
                          <li>Implement proper security headers</li>
                        </ul>
                      </div>
                    )}

                    {host.ports.some(p => p.scripts && Object.keys(p.scripts).some(k => k.includes('ssl'))) && (
                      <div className="bg-gray-700/50 p-4 rounded-lg break-words">
                        <h4 className="text-sm font-medium text-gray-300 mb-2">SSL/TLS Security</h4>
                        <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                          <li>Use strong SSL/TLS configurations</li>
                          <li>Disable weak cipher suites</li>
                          <li>Keep certificates up to date</li>
                        </ul>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          ))}
        </div>
      );
    }

    return null;
  };

  return (
    <div className="relative">
      {/* Fixed position card for advanced scanning */}
      <div className="fixed right-8 top-1/2 -translate-y-1/2 w-80 hidden lg:block">
        <Card className="bg-gray-800/95 border border-blue-500/20 backdrop-blur-sm shadow-xl">
          <CardContent className="p-6">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-5 w-5 text-blue-400" />
              <h3 className="text-lg font-semibold text-white">Need Advanced Network Security?</h3>
            </div>
            
            <div className="space-y-4">
              <p className="text-sm text-gray-300">
                Our enterprise-grade network scanning services provide:
              </p>
              
              <ul className="space-y-2 text-sm text-gray-300">
                <li className="flex items-start gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-blue-400 mt-1.5 flex-shrink-0" />
                  <span>Deep vulnerability assessment</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-blue-400 mt-1.5 flex-shrink-0" />
                  <span>Advanced threat detection</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-blue-400 mt-1.5 flex-shrink-0" />
                  <span>Custom security solutions</span>
                </li>
                <li className="flex items-start gap-2">
                  <div className="h-1.5 w-1.5 rounded-full bg-blue-400 mt-1.5 flex-shrink-0" />
                  <span>Expert security consultation</span>
                </li>
              </ul>

              <div className="pt-2">
                <a
                  href="https://virtuestech.com/contact/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center justify-center w-full px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm font-medium group"
                >
                  Contact Our Security Team
                  <ExternalLink className="h-4 w-4 ml-2 group-hover:translate-x-0.5 transition-transform" />
                </a>
              </div>

              <p className="text-xs text-gray-400 text-center mt-4">
                Powered by VirtuesTech Security Solutions
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main content with adjusted max width */}
      <section className="max-w-3xl mx-auto mb-16 mt-16 lg:mr-96" data-aos="fade-up">
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
                disabled={isScanning} // Only disable during active scanning
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
                  disabled={isScanning} // Only disable during active scanning
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

            {isScanning && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm text-gray-400">
                  <span>Scanning in progress...</span>
                  <span>{scanProgress}%</span>
                </div>
                <Progress value={scanProgress} className="h-2" />
              </div>
            )}

            <p className="text-gray-300 text-sm mb-4">
              Attempts remaining: <strong>{attempts}</strong>
            </p>

            <div className="flex justify-center gap-4">
              <button
                type="submit"
                disabled={isScanning || attempts <= 0}
                className="px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm"
              >
                {isScanning ? (
                  <>
                    <Loader className="animate-spin h-4 w-4" />
                    Scanning...
                  </>
                ) : (
                  "Start Network Scan"
                )}
              </button>

              {isScanning && (
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
    </div>
  );
};

export default NetworkScanner; 