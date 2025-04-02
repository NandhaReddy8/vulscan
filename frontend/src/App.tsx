import { useState, useEffect } from "react";
import { io, Socket } from "socket.io-client";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Header from "./components/Header";
import Footer from "./components/Footer";
import Scanner from "./components/Scanner";
import Results from "./components/Results";

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

// You may want to set this in an environment variable

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://127.0.0.1:5000";

function App() {
  const [isScanning, setIsScanning] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [socket, setSocket] = useState<Socket | null>(null);
  const [url, setUrl] = useState("");
  const [scanProgress, setScanProgress] = useState({
    progress: 0,
    message: "",
    phase: "",
  });
  const [scanError, setScanError] = useState<{
    type: string;
    error: string;
  } | null>(null);
  const [stats, setStats] = useState<ScanStats>({
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  });
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);

  useEffect(() => {
    // Configure Socket.IO with explicit options
    const socket: Socket = io(BACKEND_URL, {
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 60000,
      transports: ["websocket", "polling"], // Try WebSocket first, fall back to polling
    });

    // Connection event handlers
    socket.on("connect", () => {
      console.log("Connected to WebSocket server with ID:", socket.id);
      setSocket(socket);
    });

    socket.on("disconnect", (reason) => {
      console.log("Disconnected from WebSocket server. Reason:", reason);
    });

    socket.on("connect_error", (error) => {
      console.error("Connection error:", error);
    });

    // Server event handlers
    socket.on("scan_completed", (data) => {
      setIsScanning(false);
      setShowResults(true);
      setScanError(null);

      console.log(data, "Scan completed data received:", data);
      // Update results if available
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

      // Handle error if present
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

    socket.on("server_update", (data) => {
      console.log("Server update received:", data);
    });

    socket.io.on("error", (error) => {
      console.error("Transport error:", error);
    });

    socket.on("scan_error", (data) => {
      setIsScanning(false);
      setScanError(data);
      setShowResults(false);
      showToast(data.error, "error");
    });

    // Cleanup on component unmount
    return () => {
      socket.disconnect();
    };
  }, []);

  const handleScan = async (url: string) => {
    setIsScanning(true);
    setShowResults(false);
    setScanError(null);
    setScanProgress({
      progress: 0,
      message: "Starting scan...",
      phase: "Initializing",
    });

    try {
      // First attempt to start scan using REST API
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          session_id: socket?.id, // Include session_id from socket if available
        }),
      });

      const data = await response.json();

      if (response.ok) {
        showToast("Scan started successfully!", "success");
        // Note: We don't set showResults to true here as we'll wait for scan_completed event
      } else {
        // If REST API fails, try using socket directly
        if (socket) {
          socket.emit("start_scan", { url });
          showToast("Scan requested via WebSocket", "info");
        } else {
          throw new Error(data.error || "Failed to submit scan request");
        }
      }
    } catch (error) {
      console.error("Error submitting scan request:", error);
      setIsScanning(false);
      setScanError({
        type: "connection_error",
        error:
          error instanceof Error
            ? error.message
            : "Unable to connect to the server",
      });
      showToast("Error: Unable to connect to the server.", "error");
    }
  };

  // Use react-toastify instead of the placeholder function
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
    <div className="min-h-screen flex flex-col bg-gray-900 text-gray-100">
      <Header />

      {/* Add ToastContainer component */}
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

      <main className="flex-1 container mx-auto px-4 py-12">
        <section className="text-center mb-16" data-aos="fade-up">
          <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-blue-300 bg-clip-text text-transparent">
            Advanced & Quick Security Scanner
          </h1>
          <p className="text-xl text-gray-300">
            Comprehensive vulnerability assessment for your digital assets
          </p>
        </section>

        <Scanner
          url={url}
          setUrl={setUrl}
          onScanSubmit={handleScan}
          isLoading={isScanning}
        />

        {/* Scan Progress Indicator */}
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

        {/* Error Display */}
        {scanError && (
          <div className="error-container mt-8">
            <div
              className={`scan-error-container p-4 bg-gray-800 rounded-lg shadow-md border-l-4 ${
                scanError.type === "validation_error"
                  ? "border-yellow-500"
                  : "border-red-500"
              }`}
            >
              <div className="error-message">
                <div className="error-header flex items-center mb-2">
                  <span className="error-icon mr-2">
                    {scanError.type === "validation_error" ? "⚠️" : "❌"}
                  </span>
                  <h3 className="text-lg font-semibold text-gray-100">
                    {scanError.type === "validation_error"
                      ? "URL Validation Error"
                      : "Scan Error"}
                  </h3>
                </div>
                <p className="error-text text-gray-300">{scanError.error}</p>
                <button
                  className="retry-button mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                  onClick={() => setScanError(null)}
                >
                  Try Another URL
                </button>
              </div>
            </div>
          </div>
        )}

        <Results
          isVisible={showResults}
          vulnerabilities={vulnerabilities}
          stats={stats}
          targetUrl={url}
        />
      </main>

      <Footer />
    </div>
  );
}

export default App;
