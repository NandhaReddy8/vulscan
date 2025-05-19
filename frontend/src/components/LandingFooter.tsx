import React from 'react';
import virtuesLogo from "./assets/virtuesTech_Logo.png";

const LandingFooter = () => {
  return (
    <footer className="py-6 mt-auto border-t border-gray-200 bg-white">
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
  );
};

export default LandingFooter; 