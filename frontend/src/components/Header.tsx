import React from 'react';
import virtuesTechLogo from '../components/assets/virtuesTech_Logo.png';

const Header = () => {
  return (
    <header className="bg-white">
      <div className="container mx-auto px-6 py-6">
        <nav className="flex items-center">
            <img 
              src={virtuesTechLogo}
            alt="VirtuesTech" 
            className="h-12 w-auto"
            />
        </nav>
      </div>
    </header>
  );
};

export default Header;