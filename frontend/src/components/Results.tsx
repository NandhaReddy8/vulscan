import React, { useState } from "react";
import { AlertCircle } from "lucide-react";
import ReportRequestDialog from "./ReportRequestDialog";

interface Vulnerability {
  risk: string;
  alert_type: string;
  alert_tags: string;
  parameter?: string;
  evidence?: string;
  description: string;
  solution: string;
}

interface ScanStats {
  high: number;
  medium: number;
  low: number;
  informational: number;
}

interface ResultsProps {
  isVisible: boolean;
  vulnerabilities: Vulnerability[];
  stats: ScanStats;
  targetUrl: string; // Add this prop
}

const getRiskStyles = (risk: string) => {
  switch (risk.toLowerCase()) {
    case "high":
      return {
        border: "border-red-600",
        badge: "bg-red-900 text-red-200",
        badgeLight: "bg-red-900/50 text-red-300",
      };
    case "medium":
      return {
        border: "border-yellow-600",
        badge: "bg-yellow-900 text-yellow-200",
        badgeLight: "bg-yellow-900/50 text-yellow-300",
      };
    case "low":
      return {
        border: "border-blue-600",
        badge: "bg-blue-900 text-blue-200",
        badgeLight: "bg-blue-900/50 text-blue-300",
      };
    default:
      return {
        border: "border-gray-600",
        badge: "bg-gray-900 text-gray-200",
        badgeLight: "bg-gray-900/50 text-gray-300",
      };
  }
};

const Results: React.FC<ResultsProps> = ({
  isVisible,
  vulnerabilities,
  stats,
  targetUrl,
}) => {
  const riskOrder = ["high", "medium", "low", "informational"] as const;

  const getInitialRiskLevel = () => {
    for (const risk of riskOrder) {
      if (stats[risk] > 0) {
        return risk as "high" | "medium" | "low" | "informational";
      }
    }
    return "low" as const;
  };

  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [selectedRiskFindings, setSelectedRiskFindings] = useState<"high" | "medium" | "low" | "informational">(getInitialRiskLevel());
  
  React.useEffect(() => {
    const highestRisk = getInitialRiskLevel();
    setSelectedRiskFindings(highestRisk);
  }, [stats]);

  if (!isVisible) return null;

  // Create ordered stats entries
  const orderedStats = riskOrder.map((risk) => [risk, stats[risk]]);

  return (
    <>
      <section className="mt-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          {orderedStats.map(([type, count]) => (
            <div
              key={type}
              className={`p-6 rounded-lg shadow-md text-center border cursor-pointer hover:bg-gray-700 transition-colors ${
                selectedRiskFindings === type
                  ? "bg-gray-600"
                  : "bg-gray-800 border-gray-700"
              }`}
              onClick={() =>
                setSelectedRiskFindings(
                  type as "high" | "medium" | "low" | "informational"
                )
              }
            >
              <h3 className="text-lg font-semibold mb-2 capitalize text-gray-100">
                {type} Risk
              </h3>
              <span
                className={`text-4xl font-bold block mb-2 ${
                  type === "high"
                    ? "text-red-500"
                    : type === "medium"
                    ? "text-amber-500"
                    : type === "low"
                    ? "text-blue-500"
                    : "text-blue-400"
                }`}
              >
                {count}
              </span>
              <p className="text-gray-300">
                {type === "informational"
                  ? "Information notices"
                  : `${type} vulnerabilities detected`}
              </p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <h3 className="text-xl font-semibold mb-4 text-gray-100">
              Vulnerability Findings
            </h3>
            <div className="space-y-6">
              {riskOrder.map((riskLevel) => {
                const riskVulns = vulnerabilities.filter(
                  (v) => v.risk.toLowerCase() === riskLevel.toLowerCase()
                );

                if (riskVulns.length === 0) return null;

                if (riskLevel !== selectedRiskFindings) return null;

                const styles = getRiskStyles(riskLevel);

                return (
                  <div key={riskLevel} className="space-y-4">
                    <h4 className="text-lg font-medium text-gray-200 capitalize">
                      {riskLevel} Risk Findings ({riskVulns.length})
                    </h4>
                    {riskVulns.map((vuln, index) => (
                      <div
                        key={`${riskLevel}-${index}`}
                        className={`bg-gray-800 rounded-lg shadow-md border-l-4 ${styles.border}`}
                      >
                        <div className="p-4 border-b border-gray-700 flex justify-between items-center">
                          <div className="flex items-center gap-3">
                            <span
                              className={`px-3 py-1 rounded-full text-sm font-semibold ${styles.badge}`}
                            >
                              {vuln.risk}
                            </span>
                            <span className="font-mono text-sm bg-gray-700 px-3 py-1 rounded text-gray-200">
                              {vuln.alert_type}
                            </span>
                          </div>
                        </div>
                        <div className="p-4">
                          <dl className="space-y-4">
                            <div>
                              <dt className="font-semibold text-gray-300">
                                Alert Tags
                              </dt>
                              <dd className="mt-1 text-gray-300">
                                {vuln.alert_tags}
                              </dd>
                            </div>
                            {vuln.parameter && (
                              <div>
                                <dt className="font-semibold text-gray-300">
                                  Parameter
                                </dt>
                                <dd className="mt-1 text-gray-300">
                                  {vuln.parameter}
                                </dd>
                              </div>
                            )}
                            {vuln.evidence && (
                              <div>
                                <dt className="font-semibold text-gray-300">
                                  Evidence
                                </dt>
                                <dd className="mt-1 font-mono text-sm bg-gray-700 p-2 rounded text-gray-200">
                                  {vuln.evidence}
                                </dd>
                              </div>
                            )}
                            <div>
                              <dt className="font-semibold text-gray-300">
                                Description
                              </dt>
                              <dd className="mt-1 text-gray-300">
                                {vuln.description}
                              </dd>
                            </div>
                            <div>
                              <dt className="font-semibold text-gray-300">
                                Solution
                              </dt>
                              <dd className="mt-1 text-gray-300">
                                {vuln.solution}
                              </dd>
                            </div>
                          </dl>
                        </div>
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="bg-gradient-to-br from-blue-800 to-blue-600 rounded-lg p-6 text-white h-fit sticky top-6 border border-blue-500/30">
            <div className="bg-white/20 rounded-full w-12 h-12 flex items-center justify-center mb-4">
              <AlertCircle className="h-6 w-6" />
            </div>
            <h4 className="text-xl font-semibold mb-3">
              For detailed Report !
            </h4>
            <p className="mb-6 opacity-90">
              Your scan has identified additional security concerns that require
              attention. Access our comprehensive security report for complete
              vulnerability analysis.
            </p>
            <button
              onClick={() => setIsDialogOpen(true)}
              className="w-full bg-white/15 hover:bg-white/25 transition-colors rounded-lg py-3 px-4 flex items-center justify-between"
            >
              <span>View Complete Report</span>
              <span>→</span>
            </button>
          </div>
        </div>
      </section>

      <ReportRequestDialog
        isOpen={isDialogOpen}
        onClose={() => setIsDialogOpen(false)}
        targetUrl={targetUrl}
      />
    </>
  );
};

export default Results;
