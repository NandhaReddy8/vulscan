import React from 'react';

const Footer = () => {
  return (
    <footer className="bg-white mt-12 shadow-[0_-2px_10px_rgba(0,0,0,0.1)]">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <h2 className="text-lg font-semibold mb-4 text-black">Company</h2>
            <ul className="space-y-2">
              <li><a href="/about" className="text-gray-700 hover:text-blue-600 transition-colors">About Us</a></li>
              <li><a href="/services" className="text-gray-700 hover:text-blue-600 transition-colors">Services</a></li>
              <li><a href="/industries" className="text-gray-700 hover:text-blue-600 transition-colors">Industries</a></li>
            </ul>
          </div>
          <div>
            <h2 className="text-lg font-semibold mb-4 text-black">Services</h2>
            <ul className="space-y-2">
              <li><a href="/software-testing" className="text-gray-700 hover:text-blue-600 transition-colors">Software Testing</a></li>
              <li><a href="/cybersecurity" className="text-gray-700 hover:text-blue-600 transition-colors">Cybersecurity</a></li>
              <li><a href="/digital-transformation" className="text-gray-700 hover:text-blue-600 transition-colors">Digital Transformation</a></li>
            </ul>
          </div>
          <div>
            <h2 className="text-lg font-semibold mb-4 text-black">Contact</h2>
            <div className="space-y-2 text-gray-700">
              <p>Email: info@virtuestech.com</p>
              <p>Address: Hyderabad, India</p>
            </div>
          </div>
        </div>
        <div className="mt-8 pt-4 border-t border-gray-200 text-center text-gray-600">
          <p>&copy; {new Date().getFullYear()} VirtuesTech. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;