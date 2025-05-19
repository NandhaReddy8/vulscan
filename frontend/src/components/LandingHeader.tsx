import React from 'react';
import { Button } from "@/components/ui/button";
import virtuesTechLogo from "./assets/virtuesTech_Logo.png";

const LandingHeader = () => {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-white/90 backdrop-blur-sm h-20">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center h-full">
        <div className="flex items-center space-x-2 flex-shrink-0 h-full">
          <img
            src={virtuesTechLogo}
            alt="VirtuesTech Logo"
            className="h-12 w-auto object-contain"
          />
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-white"
          onClick={() => window.location.href = "https://virtuestech.com"}
        >
          Visit Our Website
        </Button>
      </div>
    </header>
  );
};

export default LandingHeader; 