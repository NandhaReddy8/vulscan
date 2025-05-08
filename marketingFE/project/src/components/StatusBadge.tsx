import React from 'react';
import { LeadStatus } from '../types';
import { CheckCircle, XCircle, Clock, HelpCircle } from 'lucide-react';

interface StatusBadgeProps {
  status: LeadStatus;
}

const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const getStatusConfig = () => {
    switch (status) {
      case 'ok':
        return {
          bgColor: 'bg-green-100',
          textColor: 'text-green-800',
          borderColor: 'border-green-200',
          icon: <CheckCircle className="w-4 h-4 mr-1" />,
          label: 'OK'
        };
      case 'not_interested':
        return {
          bgColor: 'bg-red-100',
          textColor: 'text-red-800',
          borderColor: 'border-red-200',
          icon: <XCircle className="w-4 h-4 mr-1" />,
          label: 'Not Interested'
        };
      case 'later':
        return {
          bgColor: 'bg-amber-100',
          textColor: 'text-amber-800',
          borderColor: 'border-amber-200',
          icon: <Clock className="w-4 h-4 mr-1" />,
          label: 'Later'
        };
      case 'not_connected':
        return {
          bgColor: 'bg-gray-100',
          textColor: 'text-gray-800',
          borderColor: 'border-gray-200',
          icon: <HelpCircle className="w-4 h-4 mr-1" />,
          label: 'Not Connected'
        };
      default:
        return {
          bgColor: 'bg-blue-100',
          textColor: 'text-blue-800',
          borderColor: 'border-blue-200',
          icon: <HelpCircle className="w-4 h-4 mr-1" />,
          label: 'Unknown'
        };
    }
  };

  const { bgColor, textColor, borderColor, icon, label } = getStatusConfig();

  return (
    <span 
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${bgColor} ${textColor} ${borderColor}`}
    >
      {icon}
      {label}
    </span>
  );
};

export default StatusBadge;