import { Button } from "@/components/ui/button";
import virtuelityLogo from "@/assets/gif.webm";

const Hero = () => {
  return (
    <div className="relative min-h-[70vh] flex items-center justify-center overflow-hidden">
      <video
        autoPlay
        muted
        loop
        playsInline
        className="absolute inset-0 w-full h-full object-cover z-0"
        style={{ filter: "brightness(0.3)" }}
      >
        <source src={virtuelityLogo} type="video/webm" />
      </video>
      <div className="container mx-auto px-4 z-10 text-center">
        <h1 className="text-4xl md:text-6xl font-bold text-white mb-6 animate-fade-in">
          Secure Every Layer of Your Digital World
        </h1>
        <h2 className="text-2xl md:text-3xl font-semibold text-blue-300 mb-8 animate-fade-in" style={{ animationDelay: "150ms" }}>
          Fast. Accurate. Comprehensive.
        </h2>
        <p className="text-lg text-blue-100 max-w-2xl mx-auto mb-8 animate-fade-in" style={{ animationDelay: "300ms" }}>
          Protect your digital assets with our advanced vulnerability scanning platform. 
          Stay one step ahead of cyber threats with real-time monitoring and analysis.
        </p>
        <Button
          className="bg-primary hover:bg-primary/90 text-white text-lg px-8 py-6 animate-fade-in"
          style={{ animationDelay: "450ms" }}
          onClick={() => window.location.href = "#scan"}
        >
          Start Your Free Scan
        </Button>
      </div>
    </div>
  );
};

export default Hero;
