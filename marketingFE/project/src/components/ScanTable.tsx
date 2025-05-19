import React, { useState } from 'react';
import { ScanResult, LeadStatus } from '../types';
import { MoreHorizontal, Check, X, Clock, HelpCircle } from 'lucide-react';

interface ScanTableProps {
  scans: ScanResult[];
  onUpdateStatus?: (scanId: string, newStatus: LeadStatus) => void;
}

const ScanTable: React.FC<ScanTableProps> = ({ scans, onUpdateStatus }) => {
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [pendingStatus, setPendingStatus] = useState<{ [id: string]: LeadStatus }>({});

  const handleStatusChange = (scanId: string, status: LeadStatus) => {
    fetch(`${import.meta.env.VITE_API_BASE_URL}/api/scan-report-summary/${scanId}/lead-status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lead_status: status }),
    })
      .then(res => res.json())
      .then(() => {
        if (onUpdateStatus) onUpdateStatus(scanId, status);
      });
  };

  const getStatusBadge = (status: LeadStatus) => {
    switch (status) {
      case 'ok':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
            <Check className="w-4 h-4 mr-1" />
            Interested
          </span>
        );
      case 'not_interested':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
            <X className="w-4 h-4 mr-1" />
            Not Interested
          </span>
        );
      case 'later':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200">
            <Clock className="w-4 h-4 mr-1" />
            Follow Up Later
          </span>
        );
      case 'not_connected':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200">
            <HelpCircle className="w-4 h-4 mr-1" />
            Not Connected
          </span>
        );
    }
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Scan Date
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              URL / IP
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Vulnerabilities
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Contact Info
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Status
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Last Contact
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Notes
            </th>
            <th className="relative px-6 py-3">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          {scans.map((scan) => (
            <tr key={scan.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">
                {new Date(scan.scanned_on).toLocaleDateString()}
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900 dark:text-gray-300">{scan.url}</div>
                <div className="text-sm text-gray-500 dark:text-gray-400">{scan.ip_address}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex flex-wrap gap-2">
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-200">
                    High: {scan.vuln_high}
                  </span>
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                    Medium: {scan.vuln_medium}
                  </span>
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                    Low: {scan.vuln_low}
                  </span>
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">
                    Info: {scan.vuln_info}
                  </span>
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900 dark:text-gray-300">{scan.user_name}</div>
                <div className="text-sm text-gray-500 dark:text-gray-400">{scan.user_email}</div>
                <div className="text-sm text-gray-500 dark:text-gray-400">{scan.user_phone}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                {getStatusBadge(scan.status)}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                {scan.last_contact ? new Date(scan.last_contact).toLocaleDateString() : 'Not contacted'}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                {scan.notes || '-'}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium relative">
                {onUpdateStatus && (
                  <>
                    <button
                      onClick={() => setActiveDropdown(activeDropdown === scan.id ? null : scan.id)}
                      className="text-gray-400 hover:text-gray-500 dark:text-gray-300 dark:hover:text-gray-200"
                      title="Change status"
                    >
                      <MoreHorizontal className="h-5 w-5" />
                    </button>
                    {activeDropdown === scan.id && (
                      <div className="absolute right-0 mt-2 w-56 rounded-md shadow-lg bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5 z-10 p-2">
                        <label htmlFor={`status-select-${scan.id}`} className="sr-only">
                          Change status
                        </label>
                        <select
                          id={`status-select-${scan.id}`}
                          title="Select status"
                          value={pendingStatus[scan.id] ?? scan.status}
                          onChange={e => setPendingStatus({ ...pendingStatus, [scan.id]: e.target.value as LeadStatus })}
                          className="block w-full mb-2 rounded border px-2 py-1"
                        >
                          <option value="ok">Interested</option>
                          <option value="not_interested">Not Interested</option>
                          <option value="later">Follow Up</option>
                          <option value="not_connected">Not Connected</option>
                        </select>
                        <button
                          onClick={() => {
                            handleStatusChange(scan.id, pendingStatus[scan.id] ?? scan.status);
                            setActiveDropdown(null);
                          }}
                          className="w-full flex items-center justify-center px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
                          title="Confirm status change"
                        >
                          <Check className="w-4 h-4 mr-1" /> Done
                        </button>
                      </div>
                    )}
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ScanTable;