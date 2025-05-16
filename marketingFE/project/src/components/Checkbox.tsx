import React from 'react';

interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string;
}

const Checkbox: React.FC<CheckboxProps> = ({ label, className = '', ...props }) => {
  return (
    <div className="flex items-center">
      <input
        type="checkbox"
        className={`h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500 transition-colors cursor-pointer ${className}`}
        {...props}
      />
      {label && (
        <label className="ml-2 block text-sm text-gray-700 cursor-pointer">
          {label}
        </label>
      )}
    </div>
  );
};

export default Checkbox;