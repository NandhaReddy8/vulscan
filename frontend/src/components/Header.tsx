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
        <nav className="hidden md:block">
          <ul className="flex gap-6">
            <li><a href="/" className="text-gray-700 hover:text-blue-600 transition-colors">Home</a></li>
            <li><a href="/about" className="text-gray-700 hover:text-blue-600 transition-colors">About Us</a></li>
            <li className="relative group">
              <a href="/services" className="text-gray-700 hover:text-blue-600 transition-colors flex items-center gap-1">
                Services <span className="text-xs">▼</span>
              </a>
              <ul className="hidden group-hover:block absolute top-full left-0 bg-white shadow-lg rounded-md min-w-[200px] py-2">
                <li><a href="/software-testing" className="block px-4 py-2 text-gray-700 hover:bg-gray-100">Software Testing</a></li>
                <li><a href="/cybersecurity" className="block px-4 py-2 text-gray-700 hover:bg-gray-100">Cybersecurity</a></li>
                <li><a href="/digital-transformation" className="block px-4 py-2 text-gray-700 hover:bg-gray-100">Digital Transformation</a></li>
              </ul>
            </li>
            <li><a href="/industries" className="text-gray-700 hover:text-blue-600 transition-colors">Industries</a></li>
            <li><a href="/contact" className="text-gray-700 hover:text-blue-600 transition-colors">Contact</a></li>
          </ul>
        </nav>
        <button className="md:hidden">
          <Menu className="h-6 w-6 text-gray-700" />
        </button>
      </div>
    </header>
  );
};

export default Header;