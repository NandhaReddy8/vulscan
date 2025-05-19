import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import ScannerPage from "./pages/ScannerPage";
import NetworkScannerPage from "./pages/NetworkScannerPage";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/webscanner" element={<ScannerPage />} />
        <Route path="/networkscanner" element={<NetworkScannerPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
