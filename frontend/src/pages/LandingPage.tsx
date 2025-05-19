import React from "react";
import LandingHeader from "@/components/LandingHeader";
import LandingFooter from "@/components/LandingFooter";
import Hero from "@/components/Hero";
import Features from "@/components/Features";

const LandingPage = () => {
  return (
    <div className="min-h-screen flex flex-col bg-white">
      <LandingHeader />
      <main className="flex-1 pt-20"> {/* pt-20 to account for fixed header */}
        <Hero />
        <Features />
      </main>
      <LandingFooter />
    </div>
  );
};

export default LandingPage; 