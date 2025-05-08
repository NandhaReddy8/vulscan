import React, { useState, useEffect } from 'react';
import { ScanResult, LeadStatus, FilterOptions } from './types';
import Header from './components/Header';
import SearchBar from './components/SearchBar';
import FilterBar from './components/FilterBar';
import ScanTable from './components/ScanTable';
import Pagination from './components/Pagination';
import StatsCard from './components/StatsCard';

function App() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [filteredScans, setFilteredScans] = useState<ScanResult[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState<FilterOptions>({
    dateRange: {
      start: '',
      end: '',
    },
    vulnerabilityLevel: 'all',
    status: 'all',
    search: '',
  });
  const [isDarkMode, setIsDarkMode] = useState(false);

  const scansPerPage = 10;

  const fetchData = () => {
    fetch(`${import.meta.env.VITE_API_BASE_URL}/api/scan-report-summary`)
      .then(res => res.json())
      .then((data) => {
        const mapped = data.map((row: any) => ({
          id: row.id,
          scanned_on: row.scanned_on,
          ip_address: row.ip_address || '',
          url: row.target_url,
          vuln_high: row.vuln_high,
          vuln_medium: row.vuln_medium,
          vuln_low: row.vuln_low,
          vuln_info: row.vuln_info,
          user_email: row.user_email || '',
          user_name: row.user_name || '',
          user_phone: row.user_phone || '',
          status: row.lead_status || 'not_contacted',
          status_color: row.status_color || 'gray',
          last_contact: row.last_updated || '',
          notes: row.notes || '',
        }));
        setScans(mapped);
      });
  };

  useEffect(() => {
    fetchData(); // Initial fetch
    const interval = setInterval(fetchData, 5000); // Poll every 5 seconds

    return () => clearInterval(interval); // Cleanup on unmount
  }, []);

  useEffect(() => {
    let result = [...scans];
    
    // Apply date range filter
    if (filters.dateRange.start) {
      result = result.filter(scan => scan.scanned_on >= filters.dateRange.start);
    }
    if (filters.dateRange.end) {
      result = result.filter(scan => scan.scanned_on <= filters.dateRange.end);
    }
    
    // Apply vulnerability level filter
    if (filters.vulnerabilityLevel !== 'all') {
      result = result.filter(scan => {
        switch (filters.vulnerabilityLevel) {
          case 'high':
            return scan.vuln_high > 0;
          case 'medium':
            return scan.vuln_medium > 0;
          case 'low':
            return scan.vuln_low > 0;
          case 'info':
            return scan.vuln_info > 0;
          default:
            return true;
        }
      });
    }

    // Apply status filter
    if (filters.status !== 'all') {
      result = result.filter(scan => scan.status === filters.status);
    }
    
    // Apply search filter
    if (filters.search) {
      const searchTerm = filters.search.toLowerCase();
      result = result.filter(
        scan =>
          scan.ip_address.toLowerCase().includes(searchTerm) ||
          scan.url.toLowerCase().includes(searchTerm) ||
          scan.user_email.toLowerCase().includes(searchTerm) ||
          scan.user_name.toLowerCase().includes(searchTerm) ||
          scan.user_phone.toLowerCase().includes(searchTerm) ||
          (scan.notes && scan.notes.toLowerCase().includes(searchTerm))
      );
    }
    
    setFilteredScans(result);
    setCurrentPage(1);
  }, [filters, scans]);
  
  const handleStatusUpdate = (scanId: string, newStatus: LeadStatus) => {
    const now = new Date().toISOString().split('T')[0];
    setScans(scans.map(scan =>
      scan.id === scanId
        ? { ...scan, status: newStatus, last_contact: now }
        : scan
    ));
  };
  
  const handleFilterChange = (filterKey: keyof FilterOptions, value: any) => {
    setFilters(prev => ({ ...prev, [filterKey]: value }));
  };
  
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };
  
  const handleExportCSV = () => {
    const headers = ['Scan Date', 'URL', 'IP Address', 'User Name', 'Email', 'Phone', 'Status', 'Last Contact', 'Notes'];
    const csvRows = [
      headers.join(','),
      ...filteredScans.map(scan => {
        return [
          scan.scanned_on,
          `"${scan.url}"`,
          scan.ip_address,
          `"${scan.user_name}"`,
          `"${scan.user_email}"`,
          `"${scan.user_phone}"`,
          scan.status,
          scan.last_contact || '',
          scan.notes ? `"${scan.notes.replace(/"/g, '""')}"` : ''
        ].join(',');
      })
    ];
    
    const csvString = csvRows.join('\n');
    const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `marketing_leads_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };
  
  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
    if (!isDarkMode) {
      document.documentElement.classList.add('dark');
      } else {
      document.documentElement.classList.remove('dark');
  }
  };

  const indexOfLastScan = currentPage * scansPerPage;
  const indexOfFirstScan = indexOfLastScan - scansPerPage;
  const currentScans = filteredScans.slice(indexOfFirstScan, indexOfLastScan);
  const totalPages = Math.ceil(filteredScans.length / scansPerPage);

  return (
<div className={`min-h-screen bg-gray-100 dark:bg-gray-900 ${isDarkMode ? 'dark' : ''}`}>
    <div className="container mx-auto px-4 py-8">
      <Header 
          title="Marketing Lead Manager" 
          isDarkMode={isDarkMode} 
          toggleDarkMode={toggleDarkMode} 
          onExport={handleExportCSV} 
        />
        
        <div className="mb-6">
          <StatsCard scans={scans} />
        </div>
        
        <div className="space-y-4 mb-6">
          <SearchBar
            value={filters.search}
            onChange={(value) => handleFilterChange('search', value)}
            placeholder="Search by name, email, phone, URL, or notes..."
          />
          
          <FilterBar
            filters={filters}
            onFilterChange={handleFilterChange}
          />
        </div>
        
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          {filteredScans.length > 0 ? (
            <>
                <ScanTable 
                scans={currentScans}
                onUpdateStatus={fetchData}
              />
                <Pagination
                currentPage={currentPage}
                totalPages={totalPages}
                onPageChange={handlePageChange}
              />
            </>
          ) : (
            <div className="py-12 px-4 text-center">
              <p className="text-gray-500 dark:text-gray-400">
                No leads found matching your filters. Try adjusting your search criteria.
              </p>
              </div>
)}
          </div>
        </div>
    </div>
  );
};

export default App;