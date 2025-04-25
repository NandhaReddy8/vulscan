
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Scan, Network, Code } from "lucide-react";

const Features = () => {
  return (
    <section className="py-20 bg-gray-50">
      <div className="container mx-auto px-4">
        <div className="text-center mb-12 animate-fade-in">
          <h2 className="text-3xl font-bold text-primary mb-4">
            Comprehensive Security Solutions
          </h2>
          <p className="text-lg text-primary-gray max-w-2xl mx-auto">
            Protect your digital assets with our advanced scanning tools. Stay ahead of cyber threats with real-time monitoring and analysis.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Website Scanner */}
          <Card className="relative overflow-hidden transition-transform hover:scale-105 animate-fade-in">
            <CardContent className="p-6 text-center">
              <Scan className="w-12 h-12 mx-auto mb-4 text-primary" />
              <h3 className="text-xl font-bold text-primary mb-3">
                Website Scanner
              </h3>
              <p className="text-primary-gray mb-6">
                Comprehensive security analysis for your web applications. Detect vulnerabilities before attackers do.
              </p>
              <Button
          className="bg-primary hover:bg-primary/90 text-white"
          onClick={() => window.location.href = "https://vas.virtuelity.com/webscanner/"}
        >
          Scan Now
        </Button>
            </CardContent>
          </Card>

          {/* Network Scanner */}
          <Card className="relative overflow-hidden opacity-75 animate-fade-in" style={{ animationDelay: "150ms" }}>
            <CardContent className="p-6 text-center">
              <div className="absolute top-4 right-4 bg-primary-gray text-white text-xs px-2 py-1 rounded">
                Coming Soon
              </div>
              <Network className="w-12 h-12 mx-auto mb-4 text-gray-400" />
              <h3 className="text-xl font-bold text-primary mb-3">
                Network Scanner
              </h3>
              <p className="text-primary-gray mb-6">
                Advanced network vulnerability assessment tool. Identify security gaps in your infrastructure.
              </p>
              <Button disabled className="bg-gray-300 text-white w-full cursor-not-allowed">
                Coming Soon
              </Button>
            </CardContent>
          </Card>

          {/* API Scanner */}
          <Card className="relative overflow-hidden opacity-75 animate-fade-in" style={{ animationDelay: "300ms" }}>
            <CardContent className="p-6 text-center">
              <div className="absolute top-4 right-4 bg-primary-gray text-white text-xs px-2 py-1 rounded">
                Coming Soon
              </div>
              <Code className="w-12 h-12 mx-auto mb-4 text-gray-400" />
              <h3 className="text-xl font-bold text-primary mb-3">
                API Scanner
              </h3>
              <p className="text-primary-gray mb-6">
                Secure your APIs with automated vulnerability detection and security testing.
              </p>
              <Button disabled className="bg-gray-300 text-white w-full cursor-not-allowed">
                Coming Soon
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
};

export default Features;
