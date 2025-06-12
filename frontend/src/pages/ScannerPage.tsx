import { useState, useEffect, useRef } from "react";
import { io, Socket } from "socket.io-client";
import { ToastContainer, toast } from "react-toastify";
import { X } from 'lucide-react';
import "react-toastify/dist/ReactToastify.css";
import Header from "@/components/Header";
import Scanner from "@/components/Scanner";
import Results from "@/components/Results";
import scannerBg from '@/components/assets/gif.webm';
import virtuesLogo from '@/components/assets/virtuesTech_Logo.png';
interface ScanStats {
  high: number;
  medium: number;
  low: number;
  informational: number;
}

interface Vulnerability {
  risk: string;
  alert_type: string;
  alert_tags: string;
  parameter?: string;
  evidence?: string;
  description: string;
  solution: string;
}

interface ScanLimitError {
  type: 'limit_exceeded' | 'connection_error' | 'validation_error';
  error: string;
  daysRemaining?: number;
}

interface ErrorDialogProps {
  error: ScanLimitError;
  onClose: () => void;
}

const ErrorDialog: React.FC<ErrorDialogProps> = ({ error, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-md p-6 relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-white"
          title='Close'
        >
          <X className="h-5 w-5" />
        </button>

        <div className="mb-6">
          <div className="flex items-center mb-4">
            <span className="text-2xl mr-3">
              {error.type === 'limit_exceeded' ? '⏳' : 
               error.type === 'validation_error' ? '⚠️' : '❌'}
            </span>
            <h3 className="text-xl font-semibold text-white">
              {error.type === 'limit_exceeded' ? 'Scan Limit Reached' :
               error.type === 'validation_error' ? 'Validation Error' : 'Scan Error'}
            </h3>
          </div>
          <p className="text-gray-300 text-lg">
            {error.error}
          </p>
        </div>

        {error.type === 'limit_exceeded' && (
          <div className="bg-gray-700/50 p-4 rounded-lg mb-6">
            <p className="text-yellow-400 font-medium">
              🕒 Please try again in {error.daysRemaining} days or reach us for complete Deep Scan.
            </p>
            <p className="text-gray-400 mt-2 text-sm">
              To ensure fair usage, we limit scans to 2 per week for each URL.
            </p>
          </div>
        )}

        <button
          onClick={onClose}
          className="w-full bg-blue-600 text-white rounded-lg px-4 py-2 hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
          Close
        </button>
      </div>
    </div>
  );
};

// Get backend URL from environment variables
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";
const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || "http://localhost:5000";

const ScannerPage = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [socket, setSocket] = useState<Socket | null>(null);
  const [url, setUrl] = useState("");
  const [scanProgress, setScanProgress] = useState({
    progress: 0,
    message: "",
    phase: "",
  });
  const [scanError, setScanError] = useState<ScanLimitError | null>(null);
  const [stats, setStats] = useState<ScanStats>({
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  });
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);

  const videoRef = useRef<HTMLVideoElement>(null);

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

  useEffect(() => {
    const socket: Socket = io(SOCKET_URL, {
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 60000,
      transports: ["websocket", "polling"],
      path: "/socket.io/",
      withCredentials: true,
      autoConnect: true,
      forceNew: true,
      extraHeaders: {
        "Origin": window.location.origin
      }
    });

    socket.on("connect", () => {
      if (import.meta.env.DEV) {
        console.log("Connected to server");
      }
      setSocket(socket);
    });

    socket.on("connect_error", () => {
      showToast("Connection error. Please try again later.", "error");
    });

    socket.on("disconnect", (reason) => {
      if (reason === "io server disconnect") {
        socket.connect();
      }
    });

    socket.on("scan_completed", (data) => {
      setIsScanning(false);
      setShowResults(true);
      setScanError(null);

      if (data.result) {
        if (data.result.summary) {
          setStats({
            informational: data.result.summary?.Informational || 0,
            high: data.result.summary?.High || 0,
            low: data.result.summary?.Low || 0,
            medium: data.result.summary?.Medium || 0,
          });
        }
        if (data.result.vulnerabilities_by_type) {
          setVulnerabilities(data.result.vulnerabilities_by_type);
        }
      }

      if (data.error) {
        showToast("Error: " + data.error, "error");
      } else {
        showToast("Scan completed successfully!", "success");
      }
    });

    socket.on("scan_progress", (data) => {
      let displayProgress = data.progress;
      let message = data.message;

      if (message.includes("Passive Scan")) {
        displayProgress = 99;
        message = `${message} (Overall Progress: 99%)`;
      } else if (data.progress === 100) {
        displayProgress = 100;
      } else {
        displayProgress = Math.min(95, Math.floor(data.progress * 0.95));
        message = `Spider Scan: ${message} (Overall Progress: ${displayProgress}%)`;
      }

      setScanProgress({
        progress: displayProgress,
        message,
        phase: data.phase || "Scanning...",
      });
    });

    socket.on("server_update", () => {
      // Silent server update handling
    });

    socket.io.on("error", () => {
      // Handle transport errors silently
    });

    socket.on("scan_error", (data) => {
      setIsScanning(false);
      setScanError(data);
      setShowResults(false);
      showToast(data.error, "error");
    });

    socket.on("scan_stopped", () => {
      setIsScanning(false);
      setScanProgress({
        progress: 0,
        message: "Scan stopped by user",
        phase: "Stopped",
      });
      showToast("Scan stopped by user", "info");
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  const handleScan = async (url: string, recaptchaToken: string) => {
    setIsScanning(true);
    setShowResults(false);
    setScanError(null);
    setUrl(url);
    setScanProgress({
      progress: 0,
      message: "Starting scan...",
      phase: "Initializing",
    });

    if (!socket?.id) {
      showToast("Error: No WebSocket connection available", "error");
      setIsScanning(false);
      return;
    }

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          url,
          session_id: socket.id,
          recaptcha_token: recaptchaToken,
        }),
      });

      const data = await response.json();

      if (response.status === 429) {
        setIsScanning(false);
        setScanError({
          type: 'limit_exceeded',
          error: data.error,
          daysRemaining: parseInt(data.error.match(/\d+/)?.[0] || '7')
        });
        return;
      }

      if (response.ok) {
        showToast("Scan started successfully!", "success");
      } else {
        throw new Error(data.error || "Failed to submit scan request");
      }
    } catch (error) {
      console.error("Error submitting scan request:", error);
      setIsScanning(false);
      setScanError({
        type: "connection_error",
        error: error instanceof Error ? error.message : "Unable to connect to the server",
      });
    }
  };

  const handleStopScan = async () => {
    if (!socket?.id) {
      showToast("Error: No WebSocket connection available", "error");
      return;
    }

    try {
      const response = await fetch(`${BACKEND_URL}/api/stop-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: socket.id,
          url: url
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setIsScanning(false);
        setScanProgress({
          progress: 0,
          message: "Scan stopped",
          phase: "Stopped",
        });
        showToast("Scan stopped successfully", "info");
      } else {
        throw new Error(data.error || "Failed to stop scan");
      }
    } catch (error) {
      console.error("Error stopping scan:", error);
      showToast(error instanceof Error ? error.message : "Error stopping scan", "error");
    }
  };

  const showToast = (message: string, type: string) => {
    switch (type) {
      case "success":
        toast.success(message, {
          position: "top-right",
          autoClose: 5000,
        });
        break;
      case "error":
        toast.error(message, {
          position: "top-right",
          autoClose: 8000,
        });
        break;
      case "info":
        toast.info(message, {
          position: "top-right",
          autoClose: 3000,
        });
        break;
      case "warning":
        toast.warning(message, {
          position: "top-right",
          autoClose: 5000,
        });
        break;
      default:
        toast(message);
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
              Vulnerability Scanner
            </h1>
            <p className="text-xl text-gray-300">
              Comprehensive vulnerability assessment for your digital assets
            </p>
          </section>

          <Scanner
            url={url}
            setUrl={setUrl}
            onScanSubmit={handleScan}
            onStopScan={handleStopScan}
            isLoading={isScanning}
          />
          
          {isScanning && (
            <div className="progress-indicator mt-8 p-4 bg-gray-800 rounded-lg shadow-md border border-gray-700">
              <div className="progress-bar bg-gray-700 rounded-full h-4 overflow-hidden">
                <div
                  className="progress bg-blue-500 h-4"
                  style={{ width: `${scanProgress.progress}%` }}
                ></div>
              </div>
              <p className="progress-message mt-2 text-gray-300">
                {scanProgress.message}
              </p>
              <p className="scan-phase text-sm text-gray-400">
                {scanProgress.phase}
              </p>
            </div>
          )}

          {scanError && (
            <ErrorDialog 
              error={scanError} 
              onClose={() => setScanError(null)} 
            />
          )}

          <Results
            isVisible={showResults}
            vulnerabilities={vulnerabilities}
            stats={stats}
            targetUrl={url}
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
};

export default ScannerPage;