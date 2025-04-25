import { Button } from "@/components/ui/button";
import virtuelityLogo from "@/assets/VirtuesTech.png";

const Header = () => {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-white/90 backdrop-blur-sm h-20">
      {/* h-20 gives the header a fixed height of 5rem (80px) */}
      <div className="container mx-auto px-4 py-4 flex justify-between items-center h-full">
        <div className="flex items-center space-x-2 flex-shrink-0 h-full">
          <img
            src={virtuelityLogo}
            alt="VirtuesTech Logo"
            className="w-[200px] h-[200px] object-contain"
          />
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-white"
          onClick={() => window.location.href = "https://virtuestech.com"}
        >
          Visit Our Website
        </Button>
      </div>
    </header>
  );
};

export default Header;