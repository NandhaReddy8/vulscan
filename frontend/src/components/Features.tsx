import React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Scan, Network, Code, Shield, Eye, Bug, LineChart, Wrench, FileText, Trophy, CloudCog } from "lucide-react";
import { useNavigate } from "react-router-dom";

const Features = () => {
  const navigate = useNavigate();

  return (
    <>
      {/* Vulnerability Scanner Section */}
      <section className="py-20 bg-gray-50">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12 animate-fade-in">
            <h2 className="text-3xl font-bold text-primary mb-4">
              Comprehensive Vulnerability Scanning
            </h2>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Our proprietary scanners are engineered to detect critical vulnerabilities with precision.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 max-w-7xl mx-auto">
            {/* Web Application Scanner */}
            <Card className="relative overflow-hidden transition-transform hover:scale-105 animate-fade-in h-full">
              <CardContent className="p-6 text-center flex flex-col justify-between h-full">
                <Scan className="w-10 h-10 mx-auto mb-3 text-primary" />
                <h3 className="text-lg font-bold text-primary mb-2">
                  Web Application Scanner
                </h3>
                <p className="text-gray-600 mb-4 text-sm">
                  Is Your Web Application Safe? Question It. Test It.
                </p>
                <Button
                  className="bg-primary hover:bg-primary/90 text-white text-sm"
                  onClick={() => navigate('/webscanner')}
                >
                  Scan Now
                </Button>
              </CardContent>
            </Card>

            {/* Network Vulnerability Scanner */}
            <Card className="relative overflow-hidden transition-transform hover:scale-105 animate-fade-in h-full" style={{ animationDelay: "150ms" }}>
              <CardContent className="p-6 text-center flex flex-col justify-between h-full">
                <Network className="w-10 h-10 mx-auto mb-3 text-primary" />
                <h3 className="text-lg font-bold text-primary mb-2">
                  Network Vulnerability Scanner
                </h3>
                <p className="text-gray-600 mb-4 text-sm">
                 Is Your Network at Risk? Scan today, Secure Tomorrow.
                </p>
                <Button
                  className="bg-primary hover:bg-primary/90 text-white text-sm"
                  onClick={() => navigate('/networkscanner')}
                >
                  Scan Now
                </Button>
              </CardContent>
            </Card>

            {/* API Scanner */}
            <Card className="relative overflow-hidden opacity-75 animate-fade-in h-full" style={{ animationDelay: "300ms" }}>
              <CardContent className="p-6 text-center flex flex-col justify-between h-full">
                <div className="absolute top-4 right-4 bg-gray-700 text-gray-300 text-xs px-2 py-1 rounded">
                  Coming Soon
                </div>
                <Code className="w-10 h-10 mx-auto mb-3 text-gray-400" />
                <h3 className="text-lg font-bold text-primary mb-2">
                  API Scanner
                </h3>
                <p className="text-gray-600 mb-4 text-sm">
                  APIs Define Your Business - We help you Secure them. 
                </p>
                <Button disabled className="bg-gray-700 text-gray-300 w-full cursor-not-allowed hover:bg-gray-700 text-sm">
                  Coming Soon
                </Button>
              </CardContent>
            </Card>

            {/* Cloud Scanner */}
            <Card className="relative overflow-hidden opacity-75 animate-fade-in h-full" style={{ animationDelay: "450ms" }}>
              <CardContent className="p-6 text-center flex flex-col justify-between h-full">
                <div className="absolute top-4 right-4 bg-gray-700 text-gray-300 text-xs px-2 py-1 rounded">
                  Coming Soon
                </div>
                <CloudCog className="w-10 h-10 mx-auto mb-3 text-gray-400" />
                <h3 className="text-lg font-bold text-primary mb-2">
                  Cloud Scanner
                </h3>
                <p className="text-gray-600 mb-4 text-sm">
                  Secure Your Cloud Infrastructure - Scan, Detect, Protect.
                </p>
                <Button disabled className="bg-gray-700 text-gray-300 w-full cursor-not-allowed hover:bg-gray-700 text-sm">
                  Coming Soon
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Cybersecurity Services Section */}
      <section className="py-20 bg-gradient-to-br from-blue-900 via-blue-800 to-blue-900">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12 animate-fade-in">
            <h2 className="text-3xl font-bold text-white mb-4">
              Professional Cybersecurity Services
            </h2>
            <p className="text-lg text-blue-100 max-w-2xl mx-auto">
              VirtueSec offers a suite of services tailored to your security needs
            </p>
          </div>
          <div className="flex flex-wrap justify-center gap-8">
            {/* Penetration Testing */}
            <Card className="bg-white/10 backdrop-blur border-0 transition-transform hover:scale-105 animate-fade-in flex-1 min-w-[280px] max-w-[400px]">
              <CardContent className="p-6 text-center">
                <Shield className="w-12 h-12 mx-auto mb-4 text-blue-300" />
                <h3 className="text-xl font-bold text-white mb-3">
                  Penetration Testing as a Service (PTaaS)
                </h3>
                <p className="text-blue-100 mb-6">
                  Simulates real-world attacks to uncover vulnerabilities in your systems, applications, and networks.
                </p>
              </CardContent>
            </Card>

            {/* Red Teaming */}
            <Card className="bg-white/10 backdrop-blur border-0 transition-transform hover:scale-105 animate-fade-in flex-1 min-w-[280px] max-w-[400px]" style={{ animationDelay: "150ms" }}>
              <CardContent className="p-6 text-center">
                <Eye className="w-12 h-12 mx-auto mb-4 text-blue-300" />
                <h3 className="text-xl font-bold text-white mb-3">
                  Red Teaming as a Service
                </h3>
                <p className="text-blue-100 mb-6">
                  Conducts simulated attacks to test your organization's detection and response capabilities.
                </p>
              </CardContent>
            </Card>

            {/* Product Security */}
            <Card className="bg-white/10 backdrop-blur border-0 transition-transform hover:scale-105 animate-fade-in flex-1 min-w-[280px] max-w-[400px]" style={{ animationDelay: "300ms" }}>
              <CardContent className="p-6 text-center">
                <Bug className="w-12 h-12 mx-auto mb-4 text-blue-300" />
                <h3 className="text-xl font-bold text-white mb-3">
                  Product Security as a Service
                </h3>
                <p className="text-blue-100 mb-6">
                  Ensures your products are secure throughout the development lifecycle.
                </p>
              </CardContent>
            </Card>

            {/* SOC as Service */}
            <Card className="bg-white/10 backdrop-blur border-0 transition-transform hover:scale-105 animate-fade-in flex-1 min-w-[280px] max-w-[400px]" style={{ animationDelay: "450ms" }}>
              <CardContent className="p-6 text-center">
                <LineChart className="w-12 h-12 mx-auto mb-4 text-blue-300" />
                <h3 className="text-xl font-bold text-white mb-3">
                  Managed Security Operations Center (SOC)
                </h3>
                <p className="text-blue-100 mb-6">
                  Provides continuous monitoring and incident response to protect your digital assets
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Why Choose Us Section */}
      <section className="py-20 bg-gray-900">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12 animate-fade-in">
            <h2 className="text-3xl font-bold text-white mb-4">
              Why Choose VirtueSec
            </h2>
            <p className="text-lg text-gray-300 max-w-2xl mx-auto">
              Industry-leading expertise combined with cutting-edge technology
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            {/* Advanced Tools */}
            <Card className="bg-gradient-to-br from-gray-800 to-gray-700 border-0 transition-all hover:shadow-xl animate-fade-in">
              <CardContent className="p-6 text-center">
                <Wrench className="w-10 h-10 mx-auto mb-4 text-blue-400" />
                <h3 className="text-lg font-bold text-white mb-2">
                  Advanced Tools & Techniques
                </h3>
                <p className="text-gray-300 text-sm">
                  Utilize cutting-edge tools and manual methodologies to uncover hidden vulnerabilities.
                </p>
              </CardContent>
            </Card>

            {/* Compliance */}
            <Card className="bg-gradient-to-br from-gray-800 to-gray-700 border-0 transition-all hover:shadow-xl animate-fade-in" style={{ animationDelay: "150ms" }}>
              <CardContent className="p-6 text-center">
                <Shield className="w-10 h-10 mx-auto mb-4 text-blue-400" />
                <h3 className="text-lg font-bold text-white mb-2">
                  Compliance-Focused Testing
                </h3>
                <p className="text-gray-300 text-sm">
                  Align your security practices with GDPR, HIPAA, PCI DSS, and other regulatory standards.
                </p>
              </CardContent>
            </Card>

            {/* Insights */}
            <Card className="bg-gradient-to-br from-gray-800 to-gray-700 border-0 transition-all hover:shadow-xl animate-fade-in" style={{ animationDelay: "300ms" }}>
              <CardContent className="p-6 text-center">
                <FileText className="w-10 h-10 mx-auto mb-4 text-blue-400" />
                <h3 className="text-lg font-bold text-white mb-2">
                  Actionable Insights
                </h3>
                <p className="text-gray-300 text-sm">
                  Deliver detailed reports with risk prioritization and actionable remediation steps.
                </p>
              </CardContent>
            </Card>

            {/* Track Record */}
            <Card className="bg-gradient-to-br from-gray-800 to-gray-700 border-0 transition-all hover:shadow-xl animate-fade-in" style={{ animationDelay: "450ms" }}>
              <CardContent className="p-6 text-center">
                <Trophy className="w-10 h-10 mx-auto mb-4 text-blue-400" />
                <h3 className="text-lg font-bold text-white mb-2">
                  Proven Track Record
                </h3>
                <p className="text-gray-300 text-sm">
                  Successfully secured systems for organizations across BFSI, healthcare, e-commerce, and more.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>
    </>
  );
};

export default Features; 