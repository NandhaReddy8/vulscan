import React from 'react';
import { Menu } from 'lucide-react';

const Header = () => {
  return (
    <header className="bg-white py-4 shadow-md">
      <div className="container mx-auto px-4 flex justify-between items-center">
        <div className="logo">
          <a href="/">
            <img 
              src="https://virtuestech.com/wp-content/uploads/2021/08/VirtuesTech-VST-1.png" 
              alt="VirtuesTech Logo"
              className="h-12"
            />
          </a>
        </div>
        <nav className="hidden md:block"></nav>
        <button className="md:hidden">
          <Menu className="h-6 w-6 text-gray-700" />
        </button>
      </div>
    </header>
  );
};

export default Header;