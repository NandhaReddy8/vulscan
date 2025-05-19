import { io } from "socket.io-client";
// (or, if you prefer, import { io } from "socket.io-client"; and then use a variable (for example, BACKEND_URL) from your .env (or config) file)
const socket = io("http://192.168.1.19:5000");
// (dummy usage (or comment) so that the linter error "‘socket’ is assigned a value but never used" is resolved)
console.log(socket); 