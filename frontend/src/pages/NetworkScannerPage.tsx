import { useState, useRef, useEffect } from "react";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Header from "../components/Header";
import NetworkScanner from "../components/NetworkScanner";
import scannerBg from '../components/assets/gif.webm';
import virtuesLogo from '../components/assets/virtuesTech_Logo.png';

function NetworkScannerPage() {
  const [isScanning, setIsScanning] = useState(false);
  const [ip, setIp] = useState("");
  const videoRef = useRef<HTMLVideoElement>(null);
  const [scanId, setScanId] = useState("");

  // Get backend URL from environment variables
  const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

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

  const handleScan = async (ip: string) => {
    setIsScanning(true);
    try {
      const response = await fetch(`${BACKEND_URL}/api/network/start-scan`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "X-Requester-IP": window.location.hostname
        },
        body: JSON.stringify({ ip_address: ip }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to start network scan");
      }

      const data = await response.json();
      setScanId(data.scan_id);
      toast.success("Network scan started successfully!", {
        position: "top-right",
        autoClose: 3000,
      });
    } catch (error) {
      console.error("Error starting network scan:", error);
      toast.error(error instanceof Error ? error.message : "Failed to start network scan", {
        position: "top-right",
        autoClose: 5000,
      });
      setIsScanning(false);
    }
  };

  const handleStopScan = async () => {
    if (!scanId) {
      toast.error("No active scan to stop", {
        position: "top-right",
        autoClose: 3000,
      });
      return;
    }

    try {
      const response = await fetch(`${BACKEND_URL}/api/network/stop-scan/${scanId}`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "X-Requester-IP": window.location.hostname
        }
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to stop scan");
      }

      setIsScanning(false);
      setScanId("");
      toast.info("Scan stopped", {
        position: "top-right",
        autoClose: 3000,
      });
    } catch (error) {
      console.error("Error stopping scan:", error);
      toast.error(error instanceof Error ? error.message : "Failed to stop scan", {
        position: "top-right",
        autoClose: 5000,
      });
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-900 text-gray-100 relative overflow-hidden">
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
            ip={ip}
            setIp={setIp}
            onScanSubmit={handleScan}
            onStopScan={handleStopScan}
            isLoading={isScanning}
            scanId={scanId}
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