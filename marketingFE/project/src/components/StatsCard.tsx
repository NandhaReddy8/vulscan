import React from 'react';
import { Check, X, Clock, HelpCircle } from 'lucide-react';
import { ScanResult } from '../types';

interface StatsCardProps {
  scans: ScanResult[];
}

const StatsCard: React.FC<StatsCardProps> = ({ scans }) => {
  const totalScans = scans.length;
  
  const getStatusCount = (status: ScanResult['status']) => {
    return scans.filter(scan => scan.status === status).length;
  };
  
  const okCount = getStatusCount('ok');
  const notInterestedCount = getStatusCount('not_interested');
  const laterCount = getStatusCount('later');
  const notConnectedCount = getStatusCount('not_connected');
  
  const okPercentage = totalScans > 0 ? Math.round((okCount / totalScans) * 100) : 0;
  const notInterestedPercentage = totalScans > 0 ? Math.round((notInterestedCount / totalScans) * 100) : 0;
  const laterPercentage = totalScans > 0 ? Math.round((laterCount / totalScans) * 100) : 0;
  const notConnectedPercentage = totalScans > 0 ? Math.round((notConnectedCount / totalScans) * 100) : 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-5 border-l-4 border-green-500">
        <div className="flex items-center">
          <div className="inline-flex items-center justify-center rounded-full bg-green-100 dark:bg-green-900 p-2 text-green-600 dark:text-green-400 flex-shrink-0">
            <Check className="h-5 w-5" />
          </div>
          <div className="ml-4">
            <h2 className="text-sm font-medium text-gray-600 dark:text-gray-300">Interested</h2>
            <div className="flex items-baseline">
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{okCount}</p>
              <p className="ml-2 text-sm text-gray-600 dark:text-gray-400">{okPercentage}%</p>
            </div>
          </div>
        </div>
      </div>
      
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-5 border-l-4 border-red-500">
        <div className="flex items-center">
          <div className="inline-flex items-center justify-center rounded-full bg-red-100 dark:bg-red-900 p-2 text-red-600 dark:text-red-400 flex-shrink-0">
            <X className="h-5 w-5" />
          </div>
          <div className="ml-4">
            <h2 className="text-sm font-medium text-gray-600 dark:text-gray-300">Not Interested</h2>
            <div className="flex items-baseline">
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{notInterestedCount}</p>
              <p className="ml-2 text-sm text-gray-600 dark:text-gray-400">{notInterestedPercentage}%</p>
            </div>
          </div>
        </div>
      </div>
      
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-5 border-l-4 border-amber-500">
        <div className="flex items-center">
          <div className="inline-flex items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900 p-2 text-amber-600 dark:text-amber-400 flex-shrink-0">
            <Clock className="h-5 w-5" />
          </div>
          <div className="ml-4">
            <h2 className="text-sm font-medium text-gray-600 dark:text-gray-300">Follow Up Later</h2>
            <div className="flex items-baseline">
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{laterCount}</p>
              <p className="ml-2 text-sm text-gray-600 dark:text-gray-400">{laterPercentage}%</p>
            </div>
          </div>
        </div>
      </div>
      
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-5 border-l-4 border-gray-500">
        <div className="flex items-center">
          <div className="inline-flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-900 p-2 text-gray-600 dark:text-gray-400 flex-shrink-0">
            <HelpCircle className="h-5 w-5" />
          </div>
          <div className="ml-4">
            <h2 className="text-sm font-medium text-gray-600 dark:text-gray-300">Not Connected</h2>
            <div className="flex items-baseline">
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{notConnectedCount}</p>
              <p className="ml-2 text-sm text-gray-600 dark:text-gray-400">{notConnectedPercentage}%</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StatsCard;