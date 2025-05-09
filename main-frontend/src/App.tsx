import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";
import virtuesLogo from "./assets/VirtuesTech.png";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
      <footer className="py-6 mt-auto border-t border-gray-800">
        <div className="container mx-auto px-4">
          <div className="flex flex-col items-center justify-center space-y-2">

            <a
              href="https://virtuestech.com"
              target="_blank"
              rel="noopener noreferrer"
              className="group flex items-center space-x-2 transition-all duration-300"
            >
              <img
                src={virtuesLogo}
                alt="VirtuesTech"
                className="h-8 w-auto transition-transform group-hover:scale-105"
              />
            </a>
            <p className="text-gray-500 text-xs">
              © 2020-2025 All Rights Reserved. VirtuesTech ® is a registered trademark of Virtue Software Technologies Private Limited​.
            </p>
          </div>
        </div>
      </footer>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
