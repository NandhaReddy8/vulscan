
import { Button } from "@/components/ui/button";

const FreeScan = () => {
  return (
    <section className="py-20 bg-white" id="scan">
      <div className="container mx-auto px-4 text-center">
        <h2 className="text-3xl md:text-4xl font-bold text-primary-gray mb-4 animate-fade-in">
          Get a Free Security Check
        </h2>
        <p className="text-xl text-primary mb-8 animate-fade-in" style={{ animationDelay: "150ms" }}>
          Experience our Website Scanner at no cost
        </p>
        <div className="max-w-md mx-auto bg-blue-50 p-6 rounded-lg shadow-lg animate-fade-in" style={{ animationDelay: "300ms" }}>
          <p className="text-primary-gray mb-6">
            Start protecting your website today with our comprehensive security scan
          </p>
          <Button
            className="bg-primary hover:bg-primary/90 text-white text-lg px-12 py-6 w-full md:w-auto"
            onClick={() => window.location.href = "https://vas.virtuelity.com/webscanner"}
          >
            Free Scan
          </Button>
        </div>
      </div>
    </section>
  );
};

export default FreeScan;
