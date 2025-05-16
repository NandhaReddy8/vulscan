import React, { useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

const Input: React.FC<InputProps> = ({ 
  label, 
  error, 
  icon, 
  className = '', 
  type = 'text',
  ...props 
}) => {
  const [showPassword, setShowPassword] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  
  const togglePasswordVisibility = () => setShowPassword(prev => !prev);
  
  const inputType = type === 'password' && showPassword ? 'text' : type;
  
  return (
    <div className="w-full">
      {label && (
        <label className="block mb-2 text-sm font-medium text-gray-700">
          {label}
        </label>
      )}
      
      <div className={`relative transition-all duration-200 ${isFocused ? 'scale-[1.01]' : ''}`}>
        {icon && (
          <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-gray-500">
            {icon}
          </div>
        )}
        
        <input
          type={inputType}
          className={`w-full px-4 py-2.5 bg-white border ${error ? 'border-red-500' : isFocused ? 'border-blue-600' : 'border-gray-500'} 
          rounded-lg focus:outline-none focus:ring-2 
          ${error ? 'focus:ring-red-200' : 'focus:ring-blue-200'} 
          transition-all duration-200 
          ${icon ? 'pl-10' : ''} 
          ${type === 'password' ? 'pr-10' : ''} 
          ${className}`}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          {...props}
        />
        
        {type === 'password' && (
          <button
            type="button"
            className="absolute inset-y-0 right-0 flex items-center pr-3 text-gray-500 hover:text-gray-700 focus:outline-none"
            onClick={togglePasswordVisibility}
          >
            {/* {showPassword ? <EyeOff size={18} /> : <Eye size={18} />} */}
          </button>
        )}
      </div>
      
      {error && (
        <p className="mt-1 text-sm text-red-600">{error}</p>
      )}
    </div>
  );
};

export default Input;