import { useState, useRef, useEffect } from "react";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Header from "../components/Header";
import NetworkScanner from "../components/NetworkScanner";
import scannerBg from '../components/assets/gif.webm';
import virtuesLogo from '../components/assets/virtuesTech_Logo.png';

// Define the scan result type
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
        device_type?: string;
        os_guesses?: Array<{
          name: string;
          accuracy: number;
        }>;
        aggressive_guesses?: Array<{
          name: string;
          accuracy: number;
        }>;
        network_distance?: number;
        service_info?: string;
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

function NetworkScannerPage() {
  const [isScanning, setIsScanning] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const [scanId, setScanId] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    if (videoRef.current) {
      if (!isScanning) {
        videoRef.current.play().catch(err => {
          console.warn('Video autoplay failed:', err);
        });
      } else {
        videoRef.current.pause();
      }
    }
  }, [isScanning]);

  // Update handler for scan completion
  const handleScanComplete = (result: ScanResult) => {
    console.log('Scan completed with result:', result);
    setScanResult(result);
    setIsScanning(false);
    // Don't clear scanId here as we need it for the results
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-900 text-gray-100 relative overflow-hidden">
      {/* Background Video */}
      <div 
        className={`fixed inset-0 w-full h-full transition-opacity duration-500 ${
          isScanning ? 'opacity-0' : 'opacity-100'
        }`}
        style={{ zIndex: 0 }}
      >
        <video
          ref={videoRef}
          autoPlay
          loop
          muted
          playsInline
          className="absolute inset-0 w-full h-full object-cover"
          style={{
            filter: 'brightness(0.3)',
            transform: 'scale(1.05)',
          }}
        >
          <source src={scannerBg} type="video/webm" />
        </video>
        <div 
          className="absolute inset-0 bg-gradient-to-b from-gray-900/20 via-gray-900/10 to-gray-900/30" 
        />
      </div>

      <div className="relative z-10">
        <Header />
        <ToastContainer
          position="top-right"
          autoClose={5000}
          hideProgressBar={false}
          newestOnTop
          closeOnClick
          rtl={false}
          pauseOnFocusLoss
          draggable
          pauseOnHover
          theme="dark"
        />

        <main className="flex-3 container mx-auto px-5 py-12">
          <section className="text-center mb-16 py-2" data-aos="fade-up">
            <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-blue-400 to-blue-300 bg-clip-text text-transparent leading-relaxed">
              Network Vulnerability Scanner
            </h1>
            <p className="text-xl text-gray-300">
              Comprehensive network security assessment for your infrastructure
            </p>
          </section>

          <NetworkScanner
            onScanComplete={handleScanComplete}
            scanId={scanId}
            isLoading={isScanning}
            scanResult={scanResult}
          />
        </main>

        <footer className="py-6 mt-auto border-t border-gray-800">
          <div className="container mx-auto px-4">
            <div className="flex flex-col items-center justify-center space-y-2">
              <a 
                href="https://virtuestech.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="group flex items-center space-x-2 transition-all duration-300"
              >
                <img 
                  src={virtuesLogo} 
                  alt="VirtuesTech" 
                  className="h-8 w-auto transition-transform group-hover:scale-105"
                />
              </a>
              <p className="text-gray-500 text-xs">
                © 2020-2025 All Rights Reserved. VirtuesTech ® is a registered trademark of Virtue Software Technologies Private Limited.
              </p>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default NetworkScannerPage; 