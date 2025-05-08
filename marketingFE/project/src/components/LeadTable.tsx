import React, { useState } from 'react';
import { Lead, LeadStatus } from '../types';
import StatusBadge from './StatusBadge';
import { ChevronDown, ChevronUp, MoreHorizontal } from 'lucide-react';

interface LeadTableProps {
  leads: Lead[];
  onUpdateStatus: (leadId: string, newStatus: LeadStatus) => void;
}

const LeadTable: React.FC<LeadTableProps> = ({ leads, onUpdateStatus }) => {
  const [sortField, setSortField] = useState<keyof Lead>('name');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [selectedLead, setSelectedLead] = useState<string | null>(null);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);

  const handleSort = (field: keyof Lead) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const sortedLeads = [...leads].sort((a, b) => {
    const aValue = a[sortField];
    const bValue = b[sortField];
    
    if (aValue === undefined && bValue === undefined) return 0;
    if (aValue === undefined) return sortDirection === 'asc' ? 1 : -1;
    if (bValue === undefined) return sortDirection === 'asc' ? -1 : 1;
    
    if (typeof aValue === 'string' && typeof bValue === 'string') {
      return sortDirection === 'asc' 
        ? aValue.localeCompare(bValue)
        : bValue.localeCompare(aValue);
    }
    
    // Default comparison for other types
    return sortDirection === 'asc'
      ? String(aValue).localeCompare(String(bValue))
      : String(bValue).localeCompare(String(aValue));
  });

  const toggleDropdown = (leadId: string) => {
    setActiveDropdown(activeDropdown === leadId ? null : leadId);
  };

  const handleStatusChange = (leadId: string, status: LeadStatus) => {
    onUpdateStatus(leadId, status);
    setActiveDropdown(null);
  };

  const getSortIcon = (field: keyof Lead) => {
    if (sortField !== field) return null;
    return sortDirection === 'asc' ? (
      <ChevronUp className="w-4 h-4 ml-1" />
    ) : (
      <ChevronDown className="w-4 h-4 ml-1" />
    );
  };

  return (
    <div className="overflow-x-auto rounded-lg shadow-sm">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th
              scope="col"
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer"
              onClick={() => handleSort('name')}
            >
              <div className="flex items-center">
                Name
                {getSortIcon('name')}
              </div>
            </th>
            <th
              scope="col"
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer"
              onClick={() => handleSort('company')}
            >
              <div className="flex items-center">
                Company
                {getSortIcon('company')}
              </div>
            </th>
            <th
              scope="col"
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer"
              onClick={() => handleSort('email')}
            >
              <div className="flex items-center">
                Email
                {getSortIcon('email')}
              </div>
            </th>
            <th
              scope="col"
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer"
              onClick={() => handleSort('status')}
            >
              <div className="flex items-center">
                Status
                {getSortIcon('status')}
              </div>
            </th>
            <th
              scope="col"
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer"
              onClick={() => handleSort('lastContact')}
            >
              <div className="flex items-center">
                Last Contact
                {getSortIcon('lastContact')}
              </div>
            </th>
            <th
              scope="col"
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer"
              onClick={() => handleSort('source')}
            >
              <div className="flex items-center">
                Source
                {getSortIcon('source')}
              </div>
            </th>
            <th scope="col" className="relative px-6 py-3">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {sortedLeads.map((lead) => (
            <tr 
              key={lead.id} 
              className={`${selectedLead === lead.id ? 'bg-blue-50' : 'hover:bg-gray-50'}`}
              onClick={() => setSelectedLead(lead.id === selectedLead ? null : lead.id)}
            >
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm font-medium text-gray-900">{lead.name}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900">{lead.company}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-500">{lead.email}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <StatusBadge status={lead.status} />
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {lead.lastContact}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {lead.source}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium relative">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleDropdown(lead.id);
                  }}
                  className="text-gray-400 hover:text-gray-500 focus:outline-none"
                >
                  <MoreHorizontal className="h-5 w-5" />
                </button>
                {activeDropdown === lead.id && (
                  <div className="absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10">
                    <div className="py-1" role="menu" aria-orientation="vertical">
                      <p className="px-4 py-2 text-xs text-gray-500">Mark as:</p>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleStatusChange(lead.id, 'ok');
                        }}
                        className="block px-4 py-2 text-sm text-left w-full hover:bg-green-50 text-green-700"
                      >
                        OK
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleStatusChange(lead.id, 'not_interested');
                        }}
                        className="block px-4 py-2 text-sm text-left w-full hover:bg-red-50 text-red-700"
                      >
                        Not Interested
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleStatusChange(lead.id, 'later');
                        }}
                        className="block px-4 py-2 text-sm text-left w-full hover:bg-amber-50 text-amber-700"
                      >
                        Later
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleStatusChange(lead.id, 'not_connected');
                        }}
                        className="block px-4 py-2 text-sm text-left w-full hover:bg-gray-50 text-gray-700"
                      >
                        Not Connected
                      </button>
                    </div>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default LeadTable;