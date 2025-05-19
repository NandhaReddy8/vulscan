import React from "react";
import { Button } from "@/components/ui/button";
import gifAnimation from "./assets/gif.webm";

const Hero = () => {
  return (
    <div className="relative min-h-[70vh] flex items-center justify-center overflow-hidden">
      {/* Background Video */}
      <video
        src={gifAnimation}
        autoPlay
        loop
        muted
        playsInline
        className="absolute inset-0 w-full h-full object-cover z-0"
        style={{ filter: "brightness(0.3)" }}
      />
      
      {/* Content */}
      <div className="container mx-auto px-4 z-10 text-center relative">
        <h1 className="text-4xl md:text-6xl font-bold text-white mb-6 animate-fade-in">
          Precision Security for Web, API, Network
        </h1>
        <h2 className="text-2xl md:text-3xl font-semibold text-blue-300 mb-8 animate-fade-in" style={{ animationDelay: "150ms" }}>
          Fast. Accurate. Comprehensive.
        </h2>
        <p className="text-lg text-blue-100 max-w-5xl mx-auto mb-8 animate-fade-in" style={{ animationDelay: "300ms" }}>
          VirtueSec delivers enterprise-grade vulnerability scanning and penetration testing services powered by AI and automation. We help businesses proactively identify and remediate security flaws across digital infrastructures—web apps, APIs, networks, and cloud environments. Our solutions reduce false positives, accelerate remediation, and ensure compliance with industry standards.
        </p>
        <Button
          className="bg-primary hover:bg-primary/90 text-white text-lg px-8 py-6 animate-fade-in"
          style={{ animationDelay: "450ms" }}
          onClick={() => {
            const scannerSection = document.querySelector('.bg-gray-50');
            if (scannerSection) {
              scannerSection.scrollIntoView({ behavior: 'smooth' });
            }
          }}
        >
          Start Your Free Scan
        </Button>
      </div>
    </div>
  );
};

export default Hero; 