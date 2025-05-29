import { useState, useEffect } from 'react';
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";

interface CapCaptchaProps {
  onVerified: (token: string) => void;
  onError: (error: string) => void;
}

type Operation = '+' | '-' | '*';

const MAX_ATTEMPTS = 5;
const ATTEMPTS_KEY = 'captcha_attempts';

const CapCaptcha: React.FC<CapCaptchaProps> = ({ onVerified, onError }) => {
  const [isComputing, setIsComputing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showMathChallenge, setShowMathChallenge] = useState(true);
  const [mathAnswer, setMathAnswer] = useState('');
  const [attempts, setAttempts] = useState(() => {
    const saved = localStorage.getItem(ATTEMPTS_KEY);
    return saved ? parseInt(saved) : 0;
  });
  const [mathProblem, setMathProblem] = useState<{
    num1: number;
    num2: number;
    operation: Operation;
    answer: number;
  } | null>(null);

  // Get backend URL from environment variables
  const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

  // Check if we're in a secure context
  const isSecureContext = window.isSecureContext;

  // Update attempts in localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem(ATTEMPTS_KEY, attempts.toString());
  }, [attempts]);

  // Generate a random math problem
  const generateMathProblem = () => {
    const operations: Operation[] = ['+', '-', '*'];
    const operation = operations[Math.floor(Math.random() * operations.length)];
    let num1 = Math.floor(Math.random() * 5) + 1; // 1-5
    let num2 = Math.floor(Math.random() * 5) + 1; // 1-5
    
    // For subtraction, ensure num1 is larger
    if (operation === '-') {
      [num1, num2] = [Math.max(num1, num2), Math.min(num1, num2)];
    }
    
    let answer: number;
    switch (operation) {
      case '+':
        answer = num1 + num2;
        break;
      case '-':
        answer = num1 - num2;
        break;
      case '*':
        answer = num1 * num2;
        break;
    }

    setMathProblem({ num1, num2, operation, answer });
  };

  // Generate initial math problem
  useEffect(() => {
    if (attempts < MAX_ATTEMPTS) {
      generateMathProblem();
    }
  }, []);

  // Helper function to check Web Crypto API availability
  const checkCryptoAvailability = (): { available: boolean; reason?: string } => {
    if (!isSecureContext) {
      return {
        available: false,
        reason: "This page must be loaded over HTTPS or localhost to use security features."
      };
    }

    if (!window.crypto) {
      return {
        available: false,
        reason: "Your browser does not support the Web Crypto API."
      };
    }

    if (!window.crypto.subtle) {
      return {
        available: false,
        reason: "Your browser's security settings are blocking access to cryptographic features."
      };
    }

    return { available: true };
  };

  // Helper function to calculate SHA-256 hash
  const calculateHash = async (data: string): Promise<string> => {
    const cryptoCheck = checkCryptoAvailability();
    if (!cryptoCheck.available) {
      throw new Error(cryptoCheck.reason);
    }

    try {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(data);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (err) {
      console.error('Hash calculation failed:', err);
      throw new Error('Failed to calculate hash. Please try a different browser or check your security settings.');
    }
  };

  const getChallenge = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/cap/challenge`);
      if (!response.ok) {
        throw new Error('Failed to get challenge');
      }
      const data = await response.json();
      setError(null);
      
      // Start computation immediately after getting challenge
      if (data.challenge) {
        findNonce(data.challenge, data.difficulty);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to get CAPTCHA challenge';
      setError(`${errorMessage}. Please try again.`);
      onError(errorMessage);
    }
  };

  const findNonce = async (currentChallenge: string, currentDifficulty: number) => {
    setIsComputing(true);
    setProgress(0);
    
    // Start time for progress calculation
    const startTime = Date.now();
    const maxTime = 10000; // 10 seconds max computation time
    
    let nonce = 0;
    const target = '0'.repeat(currentDifficulty);
    
    try {
      while (true) {
        // Check if we've exceeded max time
        if (Date.now() - startTime > maxTime) {
          throw new Error('Computation took too long');
        }
        
        // Update progress based on time elapsed
        setProgress(Math.min(((Date.now() - startTime) / maxTime) * 100, 99));
        
        // Try next nonce
        const data = `${currentChallenge}${nonce}`;
        const hash = await calculateHash(data);
        
        if (hash.startsWith(target)) {
          // Found valid nonce
          try {
            const verifyResponse = await fetch(`${BACKEND_URL}/api/cap/verify`, {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'X-Internal-Verify': 'true'
              },
              body: JSON.stringify({ challenge: currentChallenge, nonce: nonce.toString() })
            });
            
            if (!verifyResponse.ok) {
              throw new Error('Verification failed');
            }
            
            const verifyData = await verifyResponse.json();
            if (verifyData.success) {
              setProgress(100);
              onVerified(`${currentChallenge}:${nonce}`);
              setIsComputing(false);
              return;
            }
          } catch {
            throw new Error('Failed to verify solution');
          }
        }
        
        nonce++;
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'CAPTCHA computation failed';
      setError(`${errorMessage}. Please try again.`);
      onError(errorMessage);
      setIsComputing(false);
    }
  };

  const handleMathSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!mathProblem) return;

    const userAnswer = parseInt(mathAnswer);
    if (isNaN(userAnswer)) {
      setError("Please enter a valid number");
      return;
    }

    if (userAnswer === mathProblem.answer) {
      setShowMathChallenge(false);
      setError(null);
      // Reset attempts on success
      setAttempts(0);
      localStorage.removeItem(ATTEMPTS_KEY);
      getChallenge();
    } else {
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);
      
      if (newAttempts >= MAX_ATTEMPTS) {
        setError(`Too many incorrect attempts. Please try again later.`);
        onError("Maximum attempts exceeded");
      } else {
        setError(`Incorrect answer. ${MAX_ATTEMPTS - newAttempts} attempts remaining.`);
        generateMathProblem();
        setMathAnswer('');
      }
    }
  };

  const handleRetry = () => {
    const cryptoCheck = checkCryptoAvailability();
    if (!cryptoCheck.available) {
      setError(cryptoCheck.reason || 'Security features are not available');
      onError('Web Crypto API not available');
      return;
    }
    setError(null);
    if (attempts < MAX_ATTEMPTS) {
      setShowMathChallenge(true);
      generateMathProblem();
      setMathAnswer('');
    }
  };

  if (attempts >= MAX_ATTEMPTS) {
    return (
      <Alert variant="destructive">
        <AlertDescription>
          Too many incorrect attempts. Please try again later.
        </AlertDescription>
      </Alert>
    );
  }

  if (showMathChallenge && mathProblem) {
    return (
      <div className="flex flex-col w-full">
        <div className="bg-gray-700/30 p-3 rounded-lg border border-gray-600 flex items-center gap-4 w-full max-w-md">
          <span className="text-gray-300 text-sm whitespace-nowrap">Solve:</span>
          <div className="font-mono text-base bg-gray-800/50 px-4 py-1.5 rounded border border-gray-600 flex-1 flex items-center justify-between">
            <span className="flex-1">
              {mathProblem.num1} {mathProblem.operation} {mathProblem.num2} = 
            </span>
            <input
              type="number"
              value={mathAnswer}
              onChange={(e) => setMathAnswer(e.target.value)}
              placeholder="?"
              className="w-20 px-3 py-1 bg-gray-700 border border-gray-600 rounded text-gray-100 placeholder-gray-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all text-base text-center ml-2"
              autoFocus
            />
          </div>
          <button
            onClick={handleMathSubmit}
            className="px-4 py-1.5 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors text-sm whitespace-nowrap"
          >
            Verify
          </button>
        </div>
        {error && (
          <div className="text-red-400 text-sm mt-2">{error}</div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {error ? (
        <Alert variant="destructive" className="py-1.5">
          <AlertDescription className="flex flex-col space-y-1 text-xs">
            <span>{error}</span>
            {!isSecureContext && (
              <span className="text-xs">
                If you're testing locally, make sure you're using <code>localhost</code> or <code>127.0.0.1</code>.
                If you're in production, ensure the site is served over HTTPS.
              </span>
            )}
            <button
              onClick={handleRetry}
              className="px-2 py-0.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded transition-colors self-start"
            >
              Retry
            </button>
          </AlertDescription>
        </Alert>
      ) : isComputing ? (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Computing proof of work...</span>
            <span>{Math.round(progress)}%</span>
          </div>
          <Progress value={progress} className="h-1" />
        </div>
      ) : (
        <div className="text-xs text-gray-400">
          Computing proof of work...
        </div>
      )}
    </div>
  );
};

export default CapCaptcha; 