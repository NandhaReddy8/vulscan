import React from 'react';
import { Menu } from 'lucide-react';
import virtuesTechLogo from '../components/assets/virtuesTech_Logo.png';

const Header = () => {
  return (
    <header className="bg-gray-100/30 backdrop-blur-sm py-4 shadow-lg border-b border-gray-200/20">
      <div className="container mx-auto px-4 flex justify-center items-center relative">
        <div className="logo">
            <a href="/">
            <img 
              src={virtuesTechLogo}
              alt="VirtuesTech Logo"
              className="h-16"
            />
            </a>
        </div>
        <nav className="hidden md:block"></nav>
        <button className="md:hidden absolute right-4">
          <Menu className="h-6 w-6 text-gray-300 hover:text-gray-100 transition-colors" />
        </button>
      </div>
    </header>
  );
};

export default Header;