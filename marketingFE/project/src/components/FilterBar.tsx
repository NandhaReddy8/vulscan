import React from 'react';
import { Filter } from 'lucide-react';
import { FilterOptions, LeadStatus } from '../types';

interface FilterBarProps {
  filters: FilterOptions;
  onFilterChange: (filterKey: keyof FilterOptions, value: any) => void;
}

const FilterBar: React.FC<FilterBarProps> = ({ filters, onFilterChange }) => {
  const vulnerabilityLevels = [
    { value: 'all', label: 'All Levels' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'info', label: 'Info' },
  ];

  const statusOptions: { value: LeadStatus | 'all'; label: string }[] = [
    { value: 'all', label: 'All Statuses' },
    { value: 'ok', label: 'Interested' },
    { value: 'not_interested', label: 'Not Interested' },
    { value: 'later', label: 'Follow Up Later' },
    { value: 'not_connected', label: 'Not Connected' },
  ];

  return (
    <div className="flex flex-col md:flex-row space-y-2 md:space-y-0 md:space-x-4 bg-white dark:bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
      <div className="flex items-center text-gray-500 dark:text-gray-400 md:w-auto">
        <Filter className="h-5 w-5 mr-2" />
        <span className="text-sm font-medium">Filters:</span>
      </div>
      
      <div className="flex flex-1 flex-col sm:flex-row gap-2">
        <div className="flex-1">
          <label htmlFor="date-start" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Start Date
          </label>
          <input
            type="date"
            id="date-start"
            className="block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
            value={filters.dateRange.start}
            onChange={(e) => onFilterChange('dateRange', { ...filters.dateRange, start: e.target.value })}
          />
        </div>

        <div className="flex-1">
          <label htmlFor="date-end" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            End Date
          </label>
          <input
            type="date"
            id="date-end"
            className="block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
            value={filters.dateRange.end}
            onChange={(e) => onFilterChange('dateRange', { ...filters.dateRange, end: e.target.value })}
          />
        </div>
        
        <div className="flex-1">
          <label htmlFor="vulnerability-level" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Vulnerability Level
          </label>
          <select
            id="vulnerability-level"
            className="block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
            value={filters.vulnerabilityLevel}
            onChange={(e) => onFilterChange('vulnerabilityLevel', e.target.value)}
          >
            {vulnerabilityLevels.map((level) => (
              <option key={level.value} value={level.value}>
                {level.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex-1">
          <label htmlFor="status-filter" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Lead Status
          </label>
          <select
            id="status-filter"
            className="block w-full pl-3 pr-10 py-2 text-base border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
            value={filters.status}
            onChange={(e) => onFilterChange('status', e.target.value)}
          >
            {statusOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
};

export default FilterBar;